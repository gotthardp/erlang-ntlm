-module(sharepoint).
-export([get_form_digest/2, get_list_attribute/4, add_list_item/6]).

get_form_digest(Site, Credentials) ->
    case ntlm_httpc:request(post,
            {Site ++ "/_api/contextinfo",
                [{"Accept", "application/json; odata=verbose"}],
                [], []}, Credentials) of
        {ok, {{_, 200, _}, _, Body}} ->
            {ok, ContextInfo} = get_body_attribute(Body, 'GetContextWebInformation'),
            {ok, binary_to_list(proplists:get_value('FormDigestValue', ContextInfo))};
        Else ->
            {error, Else}
    end.

get_list_attribute(Site, List, Attribute, Credentials) ->
    case ntlm_httpc:request(get,
            {Site ++ "/_api/web/lists/GetByTitle('" ++ List ++ "')",
                [{"Accept", "application/json; odata=verbose"}]}, Credentials) of
        {ok, {{_, 200, _}, _, Body}} ->
            get_body_attribute(Body, Attribute);
        Else ->
            {error, Else}
    end.

add_list_item(Site, List, ListItemEntityType, ItemData, FormDigest, Credentials) ->
    Body = jsx:encode([{'__metadata',[{'type', ListItemEntityType}]} | ItemData]),
    case ntlm_httpc:request(post,
            {Site ++ "/_api/web/lists/GetByTitle('" ++ List ++ "')/items",
                [{"Accept", "application/json; odata=verbose"},
                {"X-RequestDigest", FormDigest}],
                ["application/json; odata=verbose"], Body}, Credentials) of
        {ok, {{_, 201, _}, _, _}} ->
            ok;
        Else ->
            {error, Else}
    end.

get_body_attribute(Body, Attribute) ->
    Body2 = jsx:decode(Body, [{labels, atom}]),
    Data = proplists:get_value(d, Body2), % namespace
    {ok, proplists:get_value(Attribute, Data)}.

% end of file
