-module(sharepoint).
-export([get_form_digest/2, get_list_attribute/4, add_list_item/6, update_list_item/7]).

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
            {Site ++ "/_api/web/lists/GetByTitle('" ++ encode_list(List) ++ "')",
                [{"Accept", "application/json; odata=verbose"}]}, Credentials) of
        {ok, {{_, 200, _}, _, Body}} ->
            get_body_attribute(Body, Attribute);
        Else ->
            {error, Else}
    end.

add_list_item(Site, List, ListItemEntityType, ItemData, FormDigest, Credentials) ->
    Body = jsx:encode([{'__metadata',[{'type', ListItemEntityType}]} | ItemData]),
    case ntlm_httpc:request(post,
            {Site ++ "/_api/web/lists/GetByTitle('" ++ encode_list(List) ++ "')/items",
                [{"Accept", "application/json; odata=verbose"},
                {"X-RequestDigest", FormDigest}],
                ["application/json; odata=verbose"], Body}, Credentials) of
        {ok, {{_, 201, _}, _, Body2}} ->
            % return identifier of the newly created list item
            get_body_attribute(Body2, 'Id');
        Else ->
            {error, Else}
    end.

update_list_item(Site, List, ItemId, ListItemEntityType, ItemData, FormDigest, Credentials) ->
    Body = jsx:encode([{'__metadata',[{'type', ListItemEntityType}]} | ItemData]),
    case ntlm_httpc:request(post,
            {Site ++ "/_api/web/lists/GetByTitle('" ++ encode_list(List) ++ "')/items(" ++ integer_to_list(ItemId) ++ ")",
                [{"Accept", "application/json; odata=verbose"},
                {"X-RequestDigest", FormDigest},
                {"IF-MATCH", "*"},
                {"X-HTTP-Method", "MERGE"}],
                ["application/json; odata=verbose"], Body}, Credentials) of
        {ok, {{_, 204, _}, _, _}} ->
            ok;
        Else ->
            {error, Else}
    end.

encode_list(Value) when is_list(Value) -> edoc_lib:escape_uri(Value);
encode_list(Value) when is_binary(Value) -> edoc_lib:escape_uri(binary_to_list(Value)).

get_body_attribute(Body, Attribute) ->
    Body2 = jsx:decode(Body, [{labels, atom}]),
    Data = proplists:get_value(d, Body2), % namespace
    {ok, proplists:get_value(Attribute, Data)}.

% end of file
