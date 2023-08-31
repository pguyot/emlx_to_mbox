#!/opt/erlang/erlang-current/bin/escript

-mode(compile).

main([Dir, "-o", Mbox]) ->
    Messages = filelib:fold_files(
        Dir, ".*\.emlx$", true, fun(File, Acc) -> [parse_emlx_filename(File) | Acc] end, []
    ),
    io:format("Processing ~B messages\n", [length(Messages)]),
    {ok, Output} = file:open(Mbox, [write, raw, append]),
    {Dupes, MissingRemoteID, MissingAttachments, _Tree} = lists:foldl(
        fun({MessageID, File}, Acc) ->
            try
                process_emlx_file(MessageID, File, Output, Acc)
            catch
                T:V:StackTrace ->
                    io:format("Failed to convert message ~B at ~s\n~p\n~p\n", [
                        MessageID, File, {T, V}, StackTrace
                    ]),
                    Acc
            end
        end,
        {0, 0, gb_trees:empty(), gb_trees:empty()},
        lists:sort(Messages)
    ),
    NbMissingAttachments = gb_trees:size(MissingAttachments),
    case NbMissingAttachments of
        0 ->
            ok;
        _ ->
            io:format("Lost attachments for ~B messages (~p)\n", [
                NbMissingAttachments, gb_trees:keys(MissingAttachments)
            ]),
            ok = file:write(Output, gb_trees:values(MissingAttachments))
    end,
    case Dupes of
        0 -> ok;
        _ -> io:format("Got ~B duplicates\n", [Dupes])
    end,
    case MissingRemoteID of
        0 -> ok;
        _ -> io:format("Got ~B with no remote ID\n", [MissingRemoteID])
    end,
    io:format("Eventually saved ~B messages\n", [
        gb_trees:size(_Tree) + NbMissingAttachments + MissingRemoteID
    ]),
    file:close(Output);
main(["--single", SingleMessage]) ->
    {MessageID, File} = parse_emlx_filename(SingleMessage),
    process_emlx_file(MessageID, File, stdout, {0, 0, gb_trees:empty(), gb_trees:empty()}).

parse_emlx_filename(File) ->
    Basename = filename:basename(File, ".emlx"),
    MessageID =
        case filename:basename(Basename, ".partial") of
            Basename -> list_to_integer(Basename);
            RealBasename -> list_to_integer(RealBasename)
        end,
    {MessageID, File}.

process_emlx_file(
    MessageID, File, Output, {AccDupes, AccMissingRemoteID, AccMissingAttachments, AccTree}
) ->
    Basename = filename:basename(File, ".emlx"),
    Partial =
        case filename:basename(Basename, ".partial") of
            Basename -> false;
            _RealBasename -> true
        end,
    {ok, Fd} = file:open(File, [read, binary]),
    {ok, [Length]} = io:fread(Fd, "", "~u\n"),
    {ok, Content} = file:read(Fd, Length),
    {ok, XML} = file:read(Fd, 8192),
    XMLLines = binary:split(XML, <<"\n">>, [global]),
    [
        <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?>">>,
        <<"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">">>,
        <<"<plist version=\"1.0\">">>,
        <<"<dict>">>
        | XMLLines1
    ] = XMLLines,
    {XMLDict, [<<"</plist>">>, <<>>]} = parse_dict(XMLLines1, []),
    file:close(Fd),
    {<<"flags">>, {integer, Flags}} = lists:keyfind(<<"flags">>, 1, XMLDict),
    RemoteID =
        case lists:keyfind(<<"remote-id">>, 1, XMLDict) of
            {<<"remote-id">>, {string, RemoteID0}} -> RemoteID0;
            false -> undefined
        end,
    FlagHeaders = process_flags(Flags),
    XUIDHeader = list_to_binary([<<"X-UID: ">>, integer_to_list(MessageID), <<"\n">>]),
    [Headers0, Body] = binary:split(Content, <<"\n\n">>),
    Headers = list_to_binary([Headers0, <<"\n">>]),
    RFC822MessageID = get_message_id(Headers),
    {MissingAttachment, ProcessedBody} = process_body(Headers, Body, File, Partial),
    ContentLength = byte_size(ProcessedBody),
    ContentLengthHeader = list_to_binary([
        <<"Content-Length: ">>, integer_to_list(ContentLength), <<"\n">>
    ]),
    ReturnPath =
        case binary:split(Headers, <<"\n">>) of
            [<<"Return-Path: <", ReturnPath0/binary>>, _] ->
                ReturnPath0;
            [<<"Return-path: <", ReturnPath0/binary>>, _] ->
                ReturnPath0;
            [<<"Return-path:">>, <<" <", ReturnPathTail/binary>>] ->
                hd(binary:split(ReturnPathTail, <<"\n">>));
            % default return e-mail.
            _ ->
                <<"emlx_to_mbox@unknown.invalid>">>
        end,
    [ReturnEmail, <<>>] = binary:split(ReturnPath, <<">">>),
    DateReceived =
        case lists:keyfind(<<"date-received">>, 1, XMLDict) of
            {<<"date-received">>, {integer, DateReceivedInt}} ->
                calendar:gregorian_seconds_to_datetime(
                    calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}) +
                        DateReceivedInt
                );
            false ->
                filelib:last_modified(File)
        end,
    DateReceivedStr = format_date(DateReceived),
    FromHeader = list_to_binary([<<"From ">>, ReturnEmail, <<" ">>, DateReceivedStr, <<"\n">>]),
    FinalContent = [
        FromHeader,
        Headers,
        FlagHeaders,
        XUIDHeader,
        ContentLengthHeader,
        <<"\n">>,
        ProcessedBody,
        <<"\n">>
    ],
    if
        RemoteID =:= undefined ->
            case MissingAttachment of
                true ->
                    io:format("Message ~s has no remote ID and is also missing attachment(s)\n", [
                        RFC822MessageID
                    ]);
                false ->
                    ok
            end,
            ok =
                case Output of
                    stdout ->
                        io:put_chars(FinalContent);
                    _ ->
                        file:write(Output, FinalContent)
                end,
            {AccDupes, AccMissingRemoteID + 1, AccMissingAttachments, AccTree};
        MissingAttachment ->
            case gb_trees:is_defined(RemoteID, AccTree) of
                true ->
                    {AccDupes + 1, AccMissingAttachments, AccTree};
                false ->
                    case gb_trees:is_defined(RemoteID, AccMissingAttachments) of
                        true ->
                            io:format("Warning: duplicate message with missing attachment\n"),
                            {AccDupes + 1, AccMissingAttachments, AccTree};
                        false ->
                            {AccDupes, AccMissingRemoteID,
                                gb_trees:insert(RemoteID, FinalContent, AccMissingAttachments),
                                AccTree}
                    end
            end;
        true ->
            case gb_trees:lookup(RemoteID, AccTree) of
                {value, {RFC822MessageID, Partial, _PrevousMID, FlagHeaders, ContentLength}} ->
                    {AccDupes + 1, AccMissingRemoteID, AccMissingAttachments, AccTree};
                {value,
                    {PreviousRFC822MessageID, PreviousPartial, PreviousMID, PreviousFlagHeaders,
                        PreviousContentLength}} ->
                    io:format(
                        "Warning: duplicate message ~s (~B/~B):\nmessage-id: ~s/~s\npartial: ~p/~p\nflags : ~s\nprevious flags: ~s\nlength : ~B/~B\n",
                        [
                            RemoteID,
                            MessageID,
                            PreviousMID,
                            RFC822MessageID,
                            PreviousRFC822MessageID,
                            Partial,
                            PreviousPartial,
                            FlagHeaders,
                            PreviousFlagHeaders,
                            ContentLength,
                            PreviousContentLength
                        ]
                    ),
                    {AccDupes + 1, AccMissingRemoteID, AccMissingAttachments, AccTree};
                none ->
                    ok =
                        case Output of
                            stdout ->
                                io:put_chars(FinalContent);
                            _ ->
                                file:write(Output, FinalContent)
                        end,
                    {AccDupes, AccMissingRemoteID,
                        gb_trees:delete_any(RemoteID, AccMissingAttachments),
                        gb_trees:insert(
                            RemoteID,
                            {RFC822MessageID, Partial, MessageID, FlagHeaders, ContentLength},
                            AccTree
                        )}
            end
    end.

parse_dict([<<"\t<key>", Tail/binary>>, Value | Rest], Acc) ->
    [Key, <<>>] = binary:split(Tail, <<"</key>">>),
    {ParsedValue, Rest1} = parse_value(Value, Rest),
    parse_dict(Rest1, [{Key, ParsedValue} | Acc]);
parse_dict([<<"</dict>">> | Rest], Acc) ->
    {lists:reverse(Acc), Rest}.

parse_value(<<"\t<integer>", Tail/binary>>, Rest) ->
    [IntegerBin, <<>>] = binary:split(Tail, <<"</integer>">>),
    {{integer, binary_to_integer(IntegerBin)}, Rest};
parse_value(<<"\t<real>", Tail/binary>>, Rest) ->
    [RealBin, <<>>] = binary:split(Tail, <<"</real>">>),
    Value =
        case binary:match(RealBin, <<".">>) of
            nomatch ->
                {integer, binary_to_integer(RealBin)};
            _ ->
                {real, binary_to_float(RealBin)}
        end,
    {Value, Rest};
parse_value(<<"\t<string>", Tail/binary>>, Rest) ->
    [StringBin, <<>>] = binary:split(Tail, <<"</string>">>),
    {{string, StringBin}, Rest};
parse_value(<<"\t<array>">>, Rest) ->
    {ArrayValues, [<<"\t</array>">> | Rest1]} = lists:splitwith(
        fun(ArrayValueLine) ->
            case ArrayValueLine of
                <<"\t</array>">> -> false;
                <<"\t\t", _/binary>> -> true
            end
        end,
        Rest
    ),
    ArrayValuesL = lists:map(
        fun(<<"\t", ArrayValueLine/binary>>) ->
            {Value, []} = parse_value(ArrayValueLine, []),
            Value
        end,
        ArrayValues
    ),
    {{array, ArrayValuesL}, Rest1}.

format_date({Date, Time}) ->
    DOW = calendar:day_of_the_week(Date),
    DOWText = lists:nth(DOW, ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]),
    MonthText = lists:nth(element(2, Date), [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]),
    io_lib:format("~s ~s ~2.10.0B ~2.10.0B:~2.10.0B:~2.10.0B ~4.10.0B", [
        DOWText,
        MonthText,
        element(3, Date),
        element(1, Time),
        element(2, Time),
        element(3, Time),
        element(1, Date)
    ]).

process_flags(Flags) ->
    FlagsBin = <<Flags:64>>,
    <<_Unknown:32, 0:1, _HighlightInToc:1, _JunkLevelRecorded:1, _FontSizeDelta:3, IsNotJunk:1,
        IsJunk:1, _Signed:1, _PriorityLevel:7, _AttachmentCount:6, _Redirected:1, Forwarded:1,
        _Initial:1, Draft:1, Recent:1, Flagged:1, _Encrypted:1, Answered:1, Deleted:1,
        Read:1>> = FlagsBin,
    StatusHeaderValue = list_to_binary([
        case Read of
            1 -> <<"R">>;
            0 -> <<>>
        end,
        case Recent of
            1 -> <<"">>;
            0 -> <<"O">>
        end
    ]),
    StatusHeader =
        case StatusHeaderValue of
            <<>> -> <<>>;
            StatusHeaderValueBin -> <<"Status: ", StatusHeaderValueBin/binary, "\n">>
        end,
    XStatusHeaderValue = list_to_binary([
        case Answered of
            1 -> <<"A">>;
            0 -> <<>>
        end,
        case Flagged of
            1 -> <<"F">>;
            0 -> <<>>
        end,
        case Draft of
            1 -> <<"T">>;
            0 -> <<>>
        end,
        case Deleted of
            1 -> <<"D">>;
            0 -> <<>>
        end
    ]),
    XStatusHeader =
        case XStatusHeaderValue of
            <<>> -> [];
            XStatusHeaderValueBin -> <<"X-Status: ", XStatusHeaderValueBin/binary, "\n">>
        end,
    XKeywordsHeaderValue = list_to_binary([
        case Forwarded of
            1 -> <<" $Forwarded Forwarded">>;
            0 -> <<>>
        end,
        case IsNotJunk of
            1 -> <<" $NotJunk NotJunk">>;
            0 -> <<>>
        end,
        case IsJunk of
            1 -> <<" $Junk Junk">>;
            0 -> <<>>
        end
    ]),
    XKeywordsHeader =
        case XKeywordsHeaderValue of
            <<>> -> <<>>;
            XKeywordsHeaderValueBin -> <<"X-Keywords:", XKeywordsHeaderValueBin/binary, "\n">>
        end,
    [StatusHeader, XStatusHeader, XKeywordsHeader].

find_emlxpart(File) ->
    Basename0 = filename:basename(File, ".emlx"),
    Basename = filename:basename(Basename0, ".partial"),
    Dirname = filename:dirname(File),
    Parts = filelib:wildcard(Basename ++ ".*.emlxpart", Dirname),
    case Parts of
        [] ->
            [];
        _ ->
            Attachments = lists:map(
                fun(Part) ->
                    Part0 = filename:basename(Part, ".emlxpart"),
                    PartNumberStr = string:substr(Part0, length(Basename) + 2),
                    AttachmentPath = filename:join([Dirname, Part]),
                    AttachmentPartPath = [
                        list_to_integer(Component)
                     || Component <- re:split(PartNumberStr, "\\.", [{return, list}])
                    ],
                    {AttachmentPartPath, {part, AttachmentPath}}
                end,
                Parts
            ),
            Attachments
    end.

find_opened_attachments(File) ->
    AttachmentsDir = filename:join(filename:dirname(filename:dirname(File)), "Attachments"),
    Basename = filename:basename(File, ".partial.emlx"),
    MessageAttachmentsDir = filename:join(AttachmentsDir, Basename),
    Attachments = lists:map(
        fun(AttachmentSubdir) ->
            [Attachment] = filelib:wildcard(
                "*", filename:join(MessageAttachmentsDir, AttachmentSubdir)
            ),
            AttachmentPath = filename:join([MessageAttachmentsDir, AttachmentSubdir, Attachment]),
            AttachmentPartPath = [
                list_to_integer(Component)
             || Component <- re:split(AttachmentSubdir, "\\.", [{return, list}])
            ],
            {AttachmentPartPath, {file, AttachmentPath}}
        end,
        filelib:wildcard("*", MessageAttachmentsDir)
    ),
    Attachments.

process_body(Headers, Body, File, false) ->
    % Message might be partial with .emlxpart files around (V4 format).
    Attachments = find_emlxpart(File),
    % Always process messages to scan for missing attachments (V4 format).
    process_body_with_attachments(File, Headers, Body, Attachments);
process_body(Headers, Body, File, true) ->
    OpenedAttachments = find_opened_attachments(File),
    EmlxPartAttachements = find_emlxpart(File),
    % V3 keeps both, merge them, favoring emlxpart (already encoded)
    MergedAttachments = lists:foldl(
        fun({PartPath, Attachment}, Acc) ->
            lists:keystore(PartPath, 1, Acc, {PartPath, Attachment})
        end,
        OpenedAttachments,
        EmlxPartAttachements
    ),
    process_body_with_attachments(File, Headers, Body, MergedAttachments).

process_body_with_attachments(File, Headers, Body, Attachments) ->
    ContentType = get_content_type(Headers),
    case ContentType of
        <<"multipart/", _/binary>> ->
            {Boundary, Preamble, Epilogue, Parts} = split_multiparts(ContentType, Body),
            {PartsWithAttachments, [], MissingAttachments} = insert_attachments_r(
                File, Parts, Attachments, [], false
            ),
            RewrittenBody = merge_multiparts(Boundary, Preamble, Epilogue, PartsWithAttachments),
            {MissingAttachments, RewrittenBody};
        _ when Attachments =:= [] -> {false, Body};
        _ ->
            [{[1], Attachment}] = Attachments,
            {HeadersL, BodyWithAttachment} = insert_attachment(Attachment, Headers),
            Headers = list_to_binary(HeadersL),
            {false, BodyWithAttachment}
    end.

get_content_type(Headers) -> get_header_value('Content-Type', Headers).
get_message_id(Headers) -> get_header_value(<<"Message-Id">>, Headers).

get_header_value(Key, Headers) ->
    case erlang:decode_packet(httph_bin, list_to_binary([Headers, <<"\n">>]), []) of
        {ok, {http_header, _Line, HttpField, _UnmodifiedField, Value}, Rest} ->
            case HttpField of
                Key -> Value;
                _ -> get_header_value(Key, Rest)
            end;
        {ok, {http_error, _}, Rest} ->
            get_header_value(Key, Rest);
        {ok, http_eoh, _Rest} ->
            undefined
    end.

split_multiparts(ContentType, Body) ->
    [_, BoundaryRest] = binary:split(ContentType, [<<"boundary=">>, <<"Boundary=">>]),
    Boundary =
        case BoundaryRest of
            <<"\"", BoundaryRest0/binary>> ->
                [Boundary0, _] = binary:split(BoundaryRest0, <<"\"">>),
                Boundary0;
            _ ->
                [Boundary0 | _] = binary:split(BoundaryRest, [<<";">>, <<"\n">>]),
                Boundary0
        end,
    [Preamble | Parts0] = binary:split(Body, <<"--", Boundary/binary, "\n">>, [global]),
    [LastPart0 | PartsR] = lists:reverse(Parts0),
    [LastPart | Epilogue] = binary:split(LastPart0, <<"--", Boundary/binary, "--\n">>),
    Parts = lists:reverse([LastPart | PartsR]),
    % Make sure we are able to rebuild the message identically.
    Body = merge_multiparts(Boundary, Preamble, Epilogue, Parts),
    {Boundary, Preamble, Epilogue, Parts}.

merge_multiparts(Boundary, Preamble, Epilogue0, Multiparts) ->
    Epilogue1 =
        case Epilogue0 of
            [] -> [];
            _ -> [<<"--">>, Boundary, <<"--\n">> | Epilogue0]
        end,
    list_to_binary([
        Preamble, [[<<"--">>, Boundary, <<"\n">>, Part] || Part <- Multiparts], Epilogue1
    ]).

insert_attachment({AttachmentType, AttachmentFile}, Headers) ->
    % io:format("Insert attachment ~s of type ~s\n", [AttachmentFile, AttachmentType]),
    HeaderLines = [
        HeaderLine
     || HeaderLine <- binary:split(Headers, <<"\n">>, [global]), HeaderLine =/= <<>>
    ],
    {HeaderLinesFiltered, AppleContentLength, ContentTransferEncoding, _Filename} = parse_attachment_headers(
        HeaderLines, undefined, undefined, undefined, []
    ),
    {Binary, Zipped} =
        case file:read_file(AttachmentFile) of
            {ok, Binary0} ->
                {Binary0, false};
            {error, eisdir} ->
                % Compress the directory
                _ = os:cmd(
                    "cd \"" ++ filename:dirname(AttachmentFile) ++ "\" && zip \"" ++
                        filename:basename(AttachmentFile) ++ ".zip\" \"" ++
                        filename:basename(AttachmentFile) ++ "\"/*"
                ),
                {ok, Binary0} = file:read_file(AttachmentFile ++ ".zip"),
                file:delete(AttachmentFile ++ ".zip"),
                {Binary0, true}
        end,
    ContentTransferEncodingAtom =
        case ContentTransferEncoding of
            undefined -> undefined;
            _ -> list_to_atom(string:to_lower(binary_to_list(ContentTransferEncoding)))
        end,
    Encoded =
        case AttachmentType of
            file -> encode_file(ContentTransferEncodingAtom, Binary);
            part -> list_to_binary([Binary, <<"\n">>])
        end,
    if
        AppleContentLength =:= undefined ->
            ok;
        AppleContentLength =:= byte_size(Encoded) ->
            ok;
        AppleContentLength =:= byte_size(Encoded) + 1 andalso
            ContentTransferEncoding =:= <<"base64">> ->
            ok;
        AppleContentLength =:= byte_size(Encoded) - 1 andalso
            ContentTransferEncoding =:= <<"base64">> ->
            ok;
        Zipped ->
            %io:format("AppleContentLength = ~p != byte_size(Encoded) = ~p, but zipped\n", [AppleContentLength, byte_size(Encoded)]),
            Encoded;
        true ->
            %io:format("AppleContentLength = ~p != byte_size(Encoded) = ~p\n", [AppleContentLength, byte_size(Encoded)]),
            Encoded
    end,
    {HeaderLinesFiltered, Encoded}.

parse_attachment_headers(
    [<<"X-Apple-Content-Length: ", LengthBin/binary>> | Tail],
    undefined,
    Encoding,
    Filename,
    AccFiltered
) ->
    LengthInt = binary_to_integer(LengthBin),
    parse_attachment_headers(Tail, LengthInt, Encoding, Filename, AccFiltered);
parse_attachment_headers(
    [<<"Content-Transfer-Encoding: ", TransferEncoding/binary>> = Header | Tail],
    Length,
    undefined,
    Filename,
    AccFiltered
) ->
    parse_attachment_headers(Tail, Length, TransferEncoding, Filename, [Header | AccFiltered]);
parse_attachment_headers(
    [<<"Content-Disposition: ", _/binary>> | _] = Headers,
    Length,
    TransferEncoding,
    undefined,
    AccFiltered
) ->
    {Tail, CDHeaders, Filename} = get_filename(Headers),
    CDHeadersR = lists:reverse(CDHeaders),
    parse_attachment_headers(Tail, Length, TransferEncoding, Filename, CDHeadersR ++ AccFiltered);
parse_attachment_headers([Header | Tail], Length, TransferEncoding, Filename, AccFiltered) ->
    parse_attachment_headers(Tail, Length, TransferEncoding, Filename, [Header | AccFiltered]);
parse_attachment_headers([], Length, Encoding, Filename, FilteredR) ->
    {[[Header, <<"\n">>] || Header <- lists:reverse(FilteredR)], Length, Encoding, Filename}.

get_filename(Headers) ->
    {CDHeaders, Tail} = lists:splitwith(
        fun(Header) ->
            case Header of
                <<"Content-Disposition: ", _/binary>> -> true;
                <<" ", _/binary>> -> true;
                <<"\t", _/binary>> -> true;
                _ -> false
            end
        end,
        Headers
    ),
    Filename = get_filename0(CDHeaders),
    {Tail, CDHeaders, Filename}.

get_filename0([H | Tail]) ->
    case binary:split(H, <<"filename">>) of
        [_, <<"*0", Rest0/binary>>] ->
            Filename0 = get_filename1(Rest0),
            [_, <<"*1", Rest1/binary>>] = binary:split(hd(Tail), <<"filename">>),
            nomatch = binary:match(list_to_binary(tl(Tail)), <<"filename">>),
            Filename1 = get_filename1(Rest1),
            FilenameQP = list_to_binary([Filename0, Filename1]),
            qp_decode(FilenameQP);
        [_, Rest] ->
            Filename = get_filename1(Rest),
            qp_decode(Filename);
        [H] ->
            get_filename0(Tail)
    end;
get_filename0([]) ->
    undefined.

get_filename1(<<"=\"", Rest/binary>>) ->
    [Filename, _] = binary:split(Rest, <<"\"">>),
    Filename;
get_filename1(<<"=", Rest/binary>>) ->
    [Filename | _] = binary:split(Rest, <<";">>),
    Filename;
get_filename1(<<"*=utf-8''", Rest/binary>>) ->
    [FilenameEncoded | _] = binary:split(Rest, <<";">>),
    percent_decode(FilenameEncoded);
get_filename1(<<"*=", Rest/binary>>) ->
    [Filename | _] = binary:split(Rest, <<";">>),
    Filename.

percent_decode(FilenameEncoded) ->
    Str = percent_decode0(binary_to_list(FilenameEncoded), []),
    unicode:characters_to_binary(Str).

percent_decode0([$%, D1, D2 | Tail], Acc) ->
    N = erlang:list_to_integer([D1, D2], 16),
    percent_decode0(Tail, [N | Acc]);
percent_decode0([C | Tail], Acc) ->
    percent_decode0(Tail, [C | Acc]);
percent_decode0([], Acc) ->
    lists:reverse(Acc).

qp_decode(QP) ->
    case binary:split(QP, <<"=?UTF-8?Q?">>) of
        [QP] ->
            QP;
        [Head, Tail] ->
            [Encoded, Rest] = binary:split(Tail, <<"?=">>),
            Decoded = qp_decode0(binary_to_list(Encoded), []),
            RestDecoded = qp_decode(Rest),
            list_to_binary([Head, Decoded, RestDecoded])
    end.

qp_decode0([$=, D1, D2 | Tail], Acc) ->
    N = erlang:list_to_integer([D1, D2], 16),
    qp_decode0(Tail, [N | Acc]);
qp_decode0([C | Tail], Acc) ->
    qp_decode0(Tail, [C | Acc]);
qp_decode0([], Acc) ->
    lists:reverse(Acc).

encode_file(base64, Binary) ->
    Base64Encoded = base64:encode(Binary),
    wrap_lines(Base64Encoded, 76);
encode_file('7bit', Binary) ->
    Binary;
encode_file('8bit', Binary) ->
    Binary;
encode_file('quoted-printable', Binary) ->
    quoted_printable(Binary, 76, []);
encode_file(undefined, Binary) ->
    Binary.

quoted_printable(<<_C, _Tail/binary>> = Bin, 1, Acc) ->
    quoted_printable(Bin, 76, ["=\n" | Acc]);
quoted_printable(<<C, Tail/binary>>, N, Acc) when C >= 33 andalso C =/= 61 andalso C =< 126 ->
    quoted_printable(Tail, N - 1, [C | Acc]);
quoted_printable(<<C, Next, Tail/binary>>, N, Acc) when
    C =:= 9 orelse C =:= 32 andalso Next =/= $\r andalso Next =/= $\n
->
    quoted_printable(<<Next, Tail/binary>>, N - 1, [C | Acc]);
quoted_printable(<<$\r, $\n, Tail/binary>>, _N, Acc) ->
    quoted_printable(Tail, 76, [<<"\n">> | Acc]);
quoted_printable(<<C, Tail/binary>>, N, Acc) when N > 3 ->
    quoted_printable(Tail, N - 3, [io_lib:format("=~2.16.0B", [C]) | Acc]);
quoted_printable(<<C, Tail/binary>>, N, Acc) when N =< 3 ->
    quoted_printable(Tail, 73, [io_lib:format("=\n=~2.16.0B", [C]) | Acc]);
quoted_printable(<<>>, _, Acc) ->
    list_to_binary(lists:reverse(Acc)).

wrap_lines(Text, Columns) ->
    wrap_lines0(Text, Columns, []).

wrap_lines0(Text, Columns, Acc) when byte_size(Text) > Columns ->
    {Left, Rest} = split_binary(Text, Columns),
    wrap_lines0(Rest, Columns, [[Left, <<"\r\n">>] | Acc]);
wrap_lines0(Text, _Columns, Acc) ->
    list_to_binary(lists:reverse([[Text, <<"\n">>] | Acc])).

insert_attachments_r(File, Parts, Attachments, Path, Missing) ->
    {PartsWithAttachmentsR, RemainingAttachments, FinalMissing} = lists:foldl(
        fun({Ix, Part}, {AccParts, AccRemainingAttachments, AccMissing}) ->
            [Headers0, Body] = binary:split(Part, <<"\n\n">>),
            Headers = list_to_binary([Headers0, <<"\n">>]),
            CompletePath = Path ++ [Ix],
            case lists:keyfind(CompletePath, 1, AccRemainingAttachments) of
                {CompletePath, AttachmentFile} ->
                    {RewrittenHeaders, RewrittenBody} = insert_attachment(AttachmentFile, Headers),
                    RewrittenPart = list_to_binary([RewrittenHeaders, <<"\n">>, RewrittenBody]),
                    {
                        [RewrittenPart | AccParts],
                        lists:keydelete(CompletePath, 1, AccRemainingAttachments),
                        AccMissing
                    };
                false ->
                    ContentType = get_content_type(Headers),
                    case ContentType of
                        <<"multipart/", _/binary>> ->
                            {Boundary, Preamble, Epilogue, SubParts} = split_multiparts(
                                ContentType, Body
                            ),
                            {PartsWithAttachments, NewRemainingAttachments, NewMissing} = insert_attachments_r(
                                File, SubParts, AccRemainingAttachments, CompletePath, AccMissing
                            ),
                            RewrittenBody = merge_multiparts(
                                Boundary, Preamble, Epilogue, PartsWithAttachments
                            ),
                            RewrittenPart = list_to_binary([Headers, <<"\n">>, RewrittenBody]),
                            {[RewrittenPart | AccParts], NewRemainingAttachments, NewMissing};
                        _ ->
                            case binary:match(Headers, <<"\nX-Apple-Content-Length:">>) of
                                nomatch ->
                                    {[Part | AccParts], AccRemainingAttachments, AccMissing};
                                _ ->
                                    % Try harder to recover attachment.
                                    HeaderLines = [
                                        HeaderLine
                                     || HeaderLine <- binary:split(Headers, <<"\n">>, [global]),
                                        HeaderLine =/= <<>>
                                    ],
                                    {_HeaderLinesFiltered, _AppleContentLength,
                                        _ContentTransferEncoding,
                                        Filename} = parse_attachment_headers(
                                        HeaderLines, undefined, undefined, undefined, []
                                    ),
                                    case lookup_open_attachment(Filename) of
                                        {value, AttachmentFile} ->
                                            io:format("Warning: found ~s at ~s\n", [
                                                Filename, AttachmentFile
                                            ]),
                                            {RewrittenHeaders, RewrittenBody} = insert_attachment(
                                                {file, AttachmentFile}, Headers
                                            ),
                                            RewrittenPart = list_to_binary([
                                                RewrittenHeaders, <<"\n">>, RewrittenBody
                                            ]),
                                            {
                                                [RewrittenPart | AccParts],
                                                lists:keydelete(
                                                    CompletePath, 1, AccRemainingAttachments
                                                ),
                                                AccMissing
                                            };
                                        false ->
                                            if
                                                Filename =:= undefined ->
                                                    io:format("Headers: ~s\n", [Headers]);
                                                true ->
                                                    io:format("Could not find attachment ~ts for ~s\n", [
                                                        Filename, File
                                                    ])
                                            end,
                                            {[Part | AccParts], AccRemainingAttachments, true}
                                    end
                            end
                    end
            end
        end,
        {[], Attachments, Missing},
        lists:zip(lists:seq(1, length(Parts)), Parts)
    ),
    {lists:reverse(PartsWithAttachmentsR), RemainingAttachments, FinalMissing}.

lookup_open_attachment(undefined) ->
    false;
lookup_open_attachment(File) ->
    HomeDir = os:getenv("HOME"),
    FileStr = unicode:characters_to_list(File),
    Result = os:cmd(
        "mdfind -name \"" ++ FileStr ++ "\" | grep -E '^" ++ HomeDir ++
            "/Library/Containers/com.apple.mail/Data/Library/Mail Downloads'"
    ),
    case Result of
        [] ->
            false;
        _ ->
            Results = string:tokens(Result, "\n"),
            FilteredResults = lists:filter(
                fun(ThisResult) ->
                    filename:basename(ThisResult) =:= FileStr
                end,
                Results
            ),
            case FilteredResults of
                [] -> false;
                [FirstResult | _] -> {value, FirstResult}
            end
    end.
