# Erlang client for NTLM Authentication and NTLM Over HTTP

Client-side implementation of:
 * NT LAN Manager (NTLM) Authentication Protocol [[MS-NLMP]](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/[MS-NLMP].pdf)
 * NTLM Over HTTP Protocol [[MS-NTHT]](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NTHT/[MS-NTHT].pdf)

This enables Erlang implementations to interface Microsoft SharePoint and other
Microsoft Internet Information Services (IIS) based applications. Few sample
functions are provided for interfacing the SharePoint 2013 REST API.

## Usage

### NT LAN Manager (NTLM) Authentication Protocol

#### negotiate() -> NegotiateMessage
Constructs the NTLM NEGOTIATE_MESSAGE:
 * NegotiateMessage = binary()

#### authenticate(Workstation, DomainName, UserName, Password, ChallengeMessage) -> AuthenticateMessage
Parses the NTLM CHALLENGE_MESSAGE and constructs the NTLM AUTHENTICATE_MESSAGE:
 * Workstation = workstationstring()
 * DomainName = domainstring()
 * UserName = httpc:userstring()
 * Password = httpc:passwordstring()
 * ChallengeMessage = binary()
 * AuthenticateMessage = binary()

### NTLM Over HTTP Protocol

#### ntlm_httpc:request(Method, Request, Credentials) -> {ok, Result} | {error, Reason}
Replacement of [httpc:request](http://erlang.org/doc/man/httpc.html#request-4) that supports NTLM
authentication:
 * Method = httpc:method()
 * Request = httpc:request()
 * Credentials = {workstationstring(), domainstring(), httpc:userstring(), httpc:passwordstring()}
 * Result = {status_line(), headers(), Body}
 * Body = binary()

## Copyright and Licensing

This software is distributed under the terms of the MIT License.
See the [LICENSE](LICENSE).

Copyright (c) 2016-2019 Petr Gotthard
