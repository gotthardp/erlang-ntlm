-module(ntlm_auth).
-export([negotiate/0, authenticate/5, test/0]).

-define(NEGOTIATE_HEADER, 40). % length of the fixed-size fields before payload
-define(AUTHENTICATE_HEADER, 72).

negotiate() ->
    <<"NTLMSSP", 0, 1:32/little, % NEGOTIATE_MESSAGE
        % NEGOTIATE flags in the little endian byte-order
        0:1, % NTLMSSP_NEGOTIATE_LM_KEY
        0:1, % NTLMSSP_NEGOTIATE_DATAGRAM
        0:1, % NTLMSSP_NEGOTIATE_SEAL
        0:1, % NTLMSSP_NEGOTIATE_SIGN
        0:1, % (unused)
        1:1, % NTLMSSP_REQUEST_TARGET
        1:1, % NTLM_NEGOTIATE_OEM
        1:1, % NTLMSSP_NEGOTIATE_UNICODE

        1:1, % NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        0:1, % (unused)
        0:1, % NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        0:1, % NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
        0:1, % Anonymous Connection
        0:1, % (unused)
        1:1, % NTLMSSP_NEGOTIATE_NTLM
        0:1, % (unused)

        0:1, % NTLMSSP_NEGOTIATE_TARGET_INFO
        0:1, % NTLMSSP_REQUEST_NON_NT_SESSION_KEY
        0:1, % (unused)
        0:1, % NTLMSSP_NEGOTIATE_IDENTIFY
        0:1, % NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0:1, % (unused)
        0:1, % NTLMSSP_TARGET_TYPE_SERVER
        0:1, % NTLMSSP_TARGET_TYPE_DOMAIN

        0:1, % NTLMSSP_NEGOTIATE_56
        0:1, % NTLMSSP_NEGOTIATE_KEY_EXCH
        0:1, % NTLMSSP_NEGOTIATE_128
        0:3, % (unused)
        1:1, % NTLMSSP_NEGOTIATE_VERSION
        0:1, % (unused)

        0:16, 0:16, ?NEGOTIATE_HEADER:32/little, % len, len, offset
        0:16, 0:16, ?NEGOTIATE_HEADER:32/little, % len, len, offset
        16#05, 16#02, 16#2800:16/little, 0:24, 16#0F>>. %% Windows Server 2003, build 10240

authenticate(Workstation, DomainName, UserName, Password,
    <<"NTLMSSP", 0, 2:32/little, % CHALLENGE_MESSAGE
        TargetNameLen:16/little, _:16, TargetNameOffset:32/little,

        % NEGOTIATE flags in the little endian byte-order
        NTLMSSP_NEGOTIATE_LM_KEY:1,
        NTLMSSP_NEGOTIATE_DATAGRAM:1,
        NTLMSSP_NEGOTIATE_SEAL:1,
        NTLMSSP_NEGOTIATE_SIGN:1,
        _:1, % (unused)
        NTLMSSP_REQUEST_TARGET:1,
        NTLM_NEGOTIATE_OEM:1,
        NTLMSSP_NEGOTIATE_UNICODE:1,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN:1,
        _:1, % (unused)
        NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED:1,
        NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED:1,
        Anonymous:1,
        _:1, % (unused)
        NTLMSSP_NEGOTIATE_NTLM:1,
        _:1, % (unused)
        NTLMSSP_NEGOTIATE_TARGET_INFO:1,
        NTLMSSP_REQUEST_NON_NT_SESSION_KEY:1,
        _:1, % (unused)
        NTLMSSP_NEGOTIATE_IDENTIFY:1,
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:1,
        _:1, % (unused)
        NTLMSSP_TARGET_TYPE_SERVER:1,
        NTLMSSP_TARGET_TYPE_DOMAIN:1,
        NTLMSSP_NEGOTIATE_56:1,
        NTLMSSP_NEGOTIATE_KEY_EXCH:1,
        NTLMSSP_NEGOTIATE_128:1,
        _:3, % (unused)
        NTLMSSP_NEGOTIATE_VERSION:1,
        _:1, % (unused)

        ServerChallenge:8/binary,
        _Reserved:8/binary,
        TargetInfoLen:16/little, _:16, TargetInfoOffset:32/little,
        _Payload/binary>> = ChallengeMessage) ->
    TargetName = binary:part(ChallengeMessage, TargetNameOffset, TargetNameLen),
    TargetInfo = binary:part(ChallengeMessage, TargetInfoOffset, TargetInfoLen),

    {WorkstationB, DomainNameB, UserNameB} = if
        NTLMSSP_NEGOTIATE_UNICODE == 1 ->
            {unicode(Workstation), unicode(DomainName), unicode(UserName)};
        NTLM_NEGOTIATE_OEM == 1 ->
            {list_to_binary(Workstation), list_to_binary(DomainName), list_to_binary(UserName)}
    end,

    NtChallengeResponse = desl(ntowfv1(Password), ServerChallenge), % NTLM_RESPONSE
    LmChallengeResponse = desl(lmowfv1(Password), ServerChallenge), % LM_RESPONSE
    %% LmChallengeResponse = NtChallengeResponse, % LM_RESPONSE
    EncryptedRandomSessionKey = <<>>,

    DomainNameOffset = ?AUTHENTICATE_HEADER,
    UserNameOffset = DomainNameOffset+byte_size(DomainNameB),
    WorkstationOffset = UserNameOffset+byte_size(UserNameB),
    LmChallengeResponseOffset = WorkstationOffset+byte_size(WorkstationB),
    NtChallengeResponseOffset = LmChallengeResponseOffset+byte_size(LmChallengeResponse),
    EncryptedRandomSessionKeyOffset = NtChallengeResponseOffset+byte_size(NtChallengeResponse),

    <<"NTLMSSP", 0, 3:32/little, % AUTHENTICATE_MESSAGE
        (byte_size(LmChallengeResponse)):16/little, (byte_size(LmChallengeResponse)):16/little,
            LmChallengeResponseOffset:32/little, % len, len, offset
        (byte_size(NtChallengeResponse)):16/little, (byte_size(NtChallengeResponse)):16/little,
            NtChallengeResponseOffset:32/little, % len, len, offset
        (byte_size(DomainNameB)):16/little, (byte_size(DomainNameB)):16/little,
            DomainNameOffset:32/little, % len, len, offset
        (byte_size(UserNameB)):16/little, (byte_size(UserNameB)):16/little,
            UserNameOffset:32/little, % len, len, offset
        (byte_size(WorkstationB)):16/little, (byte_size(WorkstationB)):16/little,
            WorkstationOffset:32/little, % len, len, offset
        (byte_size(EncryptedRandomSessionKey)):16/little, (byte_size(EncryptedRandomSessionKey)):16/little,
            EncryptedRandomSessionKeyOffset:32/little, % len, len, offset

        % NEGOTIATE flags in the little endian byte-order
        0:1, % NTLMSSP_NEGOTIATE_LM_KEY
        0:1, % NTLMSSP_NEGOTIATE_DATAGRAM
        0:1, % NTLMSSP_NEGOTIATE_SEAL
        0:1, % NTLMSSP_NEGOTIATE_SIGN
        0:1, % (unused)
        1:1, % NTLMSSP_REQUEST_TARGET
        NTLM_NEGOTIATE_OEM:1, % NTLM_NEGOTIATE_OEM
        NTLMSSP_NEGOTIATE_UNICODE:1, % NTLMSSP_NEGOTIATE_UNICODE
        1:1, % NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        0:1, % (unused)
        0:1, % NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        0:1, % NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
        0:1, % Anonymous Connection
        0:1, % (unused)
        1:1, % NTLMSSP_NEGOTIATE_NTLM
        0:1, % (unused)
        0:1, % NTLMSSP_NEGOTIATE_TARGET_INFO
        0:1, % NTLMSSP_REQUEST_NON_NT_SESSION_KEY
        0:1, % (unused)
        0:1, % NTLMSSP_NEGOTIATE_IDENTIFY
        0:1, % NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        0:1, % (unused)
        0:1, % NTLMSSP_TARGET_TYPE_SERVER
        0:1, % NTLMSSP_TARGET_TYPE_DOMAIN
        0:1, % NTLMSSP_NEGOTIATE_56
        0:1, % NTLMSSP_NEGOTIATE_KEY_EXCH
        0:1, % NTLMSSP_NEGOTIATE_128
        0:3, % (unused)
        1:1, % NTLMSSP_NEGOTIATE_VERSION
        0:1, % (unused)

        16#05, 16#02, 16#2800:16/little, 0:24, 16#0F, %% Windows Server 2003, build 10240, build 10240
        DomainNameB/binary, UserNameB/binary, WorkstationB/binary,
        LmChallengeResponse/binary, NtChallengeResponse/binary, EncryptedRandomSessionKey/binary>>.

% One-way function of the user's password to use as the response key.
ntowfv1(Passwd) ->
    % Define NTOWFv1(Passwd, User, UserDom) as MD4(UNICODE(Passwd))
    md4(unicode(Passwd)).

% One-way function of the user's password to use as the response key.
lmowfv1(Passwd) ->
    Passwd2 = padded(14, Passwd),
    % Define LMOWFv1(Passwd, User, UserDom) as ConcatenationOf(
    % DES(UpperCase(Passwd)[0..6],"KGS!@#$%"), DES(UpperCase(Passwd)[7..13],"KGS!@#$%"))
    <<(lmdes_half(string:sub_string(Passwd2,1,7)))/binary,
      (lmdes_half(string:sub_string(Passwd2,8,14)))/binary>>.

lmdes_half(SubStr) ->
    des(list_to_binary(uppercase(SubStr)), <<"KGS!@#$%">>).

oneif(Condition) ->
    if
        Condition -> 1;
        true -> 0
    end.

padded(Bytes, Msg) when is_list(Msg) ->
    case length(Msg) rem Bytes of
        0 -> Msg;
        N -> Msg ++ lists:duplicate(Bytes-N, 0)
    end;
padded(Bytes, Msg) when is_binary(Msg) ->
    case bit_size(Msg) rem (8*Bytes) of
        0 -> Msg;
        N -> <<Msg/bitstring, 0:(8*Bytes-N)>>
    end.

% Encryption of an 8-byte data item D with the 7-byte key K using the DES-ECB.
des(K, D) ->
    % Erlang/OpenSSL expects a key of 8 bytes with odd parity.
    % The least significant bit in each byte is the parity bit.
    crypto:block_encrypt(des_ecb, expand_des_key(K), D).

% Convert a 7-byte key to an 8-byte key with odd parity.
expand_des_key(<<B:7, R/bitstring>>) ->
    <<(check_parity(B bsl 1)), (expand_des_key(R))/bitstring>>;
expand_des_key(<<>>) ->
    <<>>.

check_parity(N) ->
    case odd_parity(N) of
        true -> N;
        false -> N bxor 1
    end.

odd_parity(N) ->
    Set = length([ 1 || <<1:1>> <= <<N>> ]),
    Set rem 2 == 1.

% Encryption of an 8-byte data item D with the 16-byte key K using the Data
% Encryption Standard Long (DESL) algorithm.
desl(K, D) ->
    % ConcatenationOf(DES(K[0..6], D), DES(K[7..13], D), DES(ConcatenationOf(K[14..15], Z(5)), D));
    <<K0:7/binary, K7:7/binary, K14:2/binary>> = K,
    <<(des(K0, D))/binary, (des(K7, D))/binary, (des(<<K14/binary, 0:(5*8)>>, D))/binary>>.

% MD4 message digest of the null-terminated byte string M
md4(M) ->
    crypto:hash(md4, M).

% 2-byte little-endian encoding of the Unicode UTF-16 representation of string.
unicode(String) ->
    unicode:characters_to_binary(String, utf8, {utf16, little}).

% Uppercase representation of string.
uppercase(String) ->
    string:to_upper(String).

% Creation of a byte array of length N, where each byte is initialized to zero.
z(N) ->
    <<0:(N*8)>>.


-include_lib("eunit/include/eunit.hrl").

crypto_test_()->
    Passwd = "Password",
    ServerChallenge = hex_to_binary(<<"0123456789abcdef">>),
    % Tests from [MS-NLMP], Section 4.2
    [
    ?_assertEqual(ntowfv1(Passwd),
        hex_to_binary(<<"a4f49c406510bdcab6824ee7c30fd852">>)),

    ?_assertEqual(lmowfv1(Passwd),
        hex_to_binary(<<"e52cac67419a9a224a3b108f3fa6cb6d">>)),

    ?_assertEqual(desl(ntowfv1(Passwd), ServerChallenge),
        hex_to_binary(<<"67c43011f30298a2ad35ece64f16331c",
                        "44bdbed927841f94">>)),

    ?_assertEqual(desl(lmowfv1(Passwd), ServerChallenge),
        hex_to_binary(<<"98def7b87f88aa5dafe2df779688a172",
                        "def11c7d5ccdef13">>))
    ].

% stackoverflow.com/questions/3768197/erlang-ioformatting-a-binary-to-hex
% a little magic from http://stackoverflow.com/users/2760050/himangshuj
binary_to_hex(Id) ->
    << <<Y>> || <<X:4>> <= Id, Y <- integer_to_list(X,16)>>.

hex_to_binary(Id) ->
    <<<<Z>> || <<X:8,Y:8>> <= Id,Z <- [binary_to_integer(<<X,Y>>,16)]>>.

% end of file
