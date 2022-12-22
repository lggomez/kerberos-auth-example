# Kerberos proxy authentication example

This is the demonstration of authentication against kerberos-enabled proxy with Java's Krb5LoginModule, using JAAS and JGSS

This fork has many improvements over the original:
* Updated code and dependencies
* Added 2 demo flavors (see below sections)
* JAAS dependency removed: For simplicity purposes, the authentication code is JGSS-based, for the sake the SPNEGO token generation only. Credentials are simply handled via user/password given to the `KerberosCallbackHandler`

## Demo flavors
 * **apachehc4**: Single project using apachehc4 and seamlessly against its own internals JGSS wrapper. Not compatible with websocket services due to the client not offering the feature, though
 * **okhttp3**: Single project using okhttp3 4.x. It has both HTTP and WebSocket compatible testing flows, and a custom authentication which is a JGSS wrapper itself to generate the SPNEGO tokens

## Prerequisites

### Kerberos

You need to have running kerberos authentication server.
If you don't want to install your own Kerberos and just need something
quick to try then you can use [demo freeIPA server](https://ipa.demo1.freeipa.org).

### Proxy server

You need to have a proxy with kerberos authentication in place.

One such proxy is Squid - see [Proxy Authentication](http://wiki.squid-cache.org/Features/Authentication) for more details

## Configuration

Required setup for KDC and JGSS/JAAS credentials - Have these in place and with a correct configuration:
 * `/etc/krb5.conf`
 * Proxy and principal/password: All project mains contain the constaints `USER`, `PASSWORD`, `PROXY_HOST` and `PROXY_PORT`. Also, change `HTTP_HOST` and `WS_HOST` if you want to test against custom services
 
The flag `RUN_HTTP_INSTEADOF_WS` constant determines wheter to run the HTTP client or the WS one, to test the desired flow. `REQUEST_RETRIES` determines the number of request retries on HTTP and messages on WS

## Running

Run the Main class corresponding to each project
