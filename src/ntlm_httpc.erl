%
% Copyright (c) 2016-2019 Petr Gotthard <petr.gotthard@centrum.cz>
% All rights reserved.
% Distributed under the terms of the MIT License. See the LICENSE file.
%
-module(ntlm_httpc).
-export([request/3]).

request(Method, Request, Credentials) ->
    Request2 = request_add_header(Request,
        {"User-Agent", "Mozilla/5.0 (Erlang/OTP)"}),
    case httpc:request(Method, Request2, [], [{body_format, binary}]) of
        {ok, {{_Ver, 401, _Phrase}, Headers, _Body}} = Response ->
            case www_authenticate(Headers) of
                ["Basic"|_] -> request_basic(Method, Request2, Credentials);
                ["NTLM"] -> request_ntlm(Method, Request2, Credentials);
                undefined -> Response
            end;
        OtherResponse -> OtherResponse
    end.

request_basic(Method, Request, Credentials) ->
    {_Workstation, _DomainName, UserName, Password} = Credentials,
    Request2 = request_add_header(Request,
        {"Authorization", "Basic " ++ base64:encode_to_string(lists:concat(UserName, ":", Password))}),
    httpc:request(Method, Request2, [], [{body_format, binary}]).

request_ntlm(Method, Request, Credentials) ->
    Request2 = request_add_header(Request,
        {"Authorization", "NTLM " ++ base64:encode_to_string(ntlm_auth:negotiate())}),
    case httpc:request(Method, Request2, [], [{body_format, binary}]) of
        {ok, {{_Ver, 401, _Phrase}, Headers, _Body}} = Response ->
            case www_authenticate(Headers) of
                ["NTLM", Binary] ->
                    {Workstation, DomainName, UserName, Password} = Credentials,
                    Request3 = request_add_header(Request,
                        {"Authorization", "NTLM " ++ base64:encode_to_string(
                            ntlm_auth:authenticate(Workstation, DomainName, UserName, Password,
                                base64:decode(Binary)))}),
                    httpc:request(Method, Request3, [], [{body_format, binary}]);
                undefined -> Response
            end;
        OtherResponse -> OtherResponse
    end.

request_add_header(Request, UserAgent) ->
    case Request of
        {Url, Headers} ->
            {Url, [UserAgent|Headers]};
        {Url, Headers, ContentType, Body} ->
            {Url, [UserAgent|Headers], ContentType, Body}
    end.

www_authenticate(Headers) ->
    case proplists:get_value("www-authenticate", Headers) of
        undefined -> undefined;
        Value -> string:tokens(Value, " ")
    end.

% end of file
