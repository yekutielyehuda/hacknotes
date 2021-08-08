# HTTP Headers

## HTTP Headers

MDN Web Docs HTTP Headers:

{% embed url="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers" %}

The text below is completely from [Wikipedia](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields):



#### Standard request fields

<table>
  <thead>
    <tr>
      <th style="text-align:left">Name</th>
      <th style="text-align:left">Description</th>
      <th style="text-align:left">Example</th>
      <th style="text-align:left">Status</th>
      <th style="text-align:left">Standard</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">A-IM</td>
      <td style="text-align:left">Acceptable instance-manipulations for the request.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc3229-10">[10]</a>
      </td>
      <td style="text-align:left"><code>A-IM: feed</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc3229">3229</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Accept</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Media_type">Media type(s)</a> that
        is/are acceptable for the response. See <a href="https://en.wikipedia.org/wiki/Content_negotiation">Content negotiation</a>.</td>
      <td
      style="text-align:left"><code>Accept: text/html</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc2616">2616</a>,
          <a
          href="https://datatracker.ietf.org/doc/html/rfc7231">7231</a>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">Accept-Charset</td>
      <td style="text-align:left">Character sets that are acceptable.</td>
      <td style="text-align:left"><code>Accept-Charset: utf-8</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc2616">2616</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Accept-Datetime</td>
      <td style="text-align:left">Acceptable version in time.</td>
      <td style="text-align:left"><code>Accept-Datetime: Thu, 31 May 2007 20:35:00 GMT</code>
      </td>
      <td style="text-align:left">Provisional</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc7089">7089</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Accept-Encoding</td>
      <td style="text-align:left">List of acceptable encodings. See <a href="https://en.wikipedia.org/wiki/HTTP_compression">HTTP compression</a>.</td>
      <td
      style="text-align:left"><code>Accept-Encoding: gzip, deflate</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc2616">2616</a>,
          <a
          href="https://datatracker.ietf.org/doc/html/rfc7231">7231</a>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">Accept-Language</td>
      <td style="text-align:left">List of acceptable human languages for response. See <a href="https://en.wikipedia.org/wiki/Content_negotiation">Content negotiation</a>.</td>
      <td
      style="text-align:left"><code>Accept-Language: en-US</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc2616">2616</a>,
          <a
          href="https://datatracker.ietf.org/doc/html/rfc7231">7231</a>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">Access-Control-Request-Method,
        <br />Access-Control-Request-Headers<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-CORS-11">[11]</a>
      </td>
      <td style="text-align:left">Initiates a request for <a href="https://en.wikipedia.org/wiki/Cross-origin_resource_sharing">cross-origin resource sharing</a> with
        <a
        href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#origin-request-header">Origin</a>(below).</td>
      <td style="text-align:left"><code>Access-Control-Request-Method: GET</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Authorization</td>
      <td style="text-align:left">Authentication credentials for <a href="https://en.wikipedia.org/wiki/Basic_access_authentication">HTTP authentication</a>.</td>
      <td
      style="text-align:left"><code>Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Cache-Control">Cache-Control</a>
      </td>
      <td style="text-align:left">Used to specify directives that must be obeyed by all caching mechanisms
        along the request-response chain.</td>
      <td style="text-align:left"><code>Cache-Control: no-cache</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Connection</td>
      <td style="text-align:left">
        <p>Control options for the current connection and list of hop-by-hop request
          fields.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7230_connection-12">[12]</a>
        </p>
        <p>Must not be used with HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left">
        <p><code>Connection: keep-alive</code>
        </p>
        <p><a href="https://en.wikipedia.org/wiki/HTTP/1.1_Upgrade_header"><code>Connection: Upgrade</code></a>
        </p>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Encoding</td>
      <td style="text-align:left">The type of encoding used on the data. See <a href="https://en.wikipedia.org/wiki/HTTP_compression">HTTP compression</a>.</td>
      <td
      style="text-align:left"><code>Content-Encoding: gzip</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Length</td>
      <td style="text-align:left">The length of the request body in <a href="https://en.wikipedia.org/wiki/Octet_(computing)">octets</a> (8-bit
        bytes).</td>
      <td style="text-align:left"><code>Content-Length: 348</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-MD5</td>
      <td style="text-align:left">A <a href="https://en.wikipedia.org/wiki/Base64">Base64</a>-encoded binary
        <a
        href="https://en.wikipedia.org/wiki/MD5">MD5</a>sum of the content of the request body.</td>
      <td style="text-align:left"><code>Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==</code>
      </td>
      <td style="text-align:left">Obsolete<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-tools.ietf.org-14">[14]</a>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Type</td>
      <td style="text-align:left">The <a href="https://en.wikipedia.org/wiki/Media_type">Media type</a> of
        the body of the request (used with POST and PUT requests).</td>
      <td style="text-align:left"><code>Content-Type: application/x-www-form-urlencoded</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Cookie</td>
      <td style="text-align:left">An <a href="https://en.wikipedia.org/wiki/HTTP_cookie">HTTP cookie</a> previously
        sent by the server with <a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#innerlink_set-cookie">Set-Cookie</a> (below).</td>
      <td
      style="text-align:left"><code>Cookie: $Version=1; Skin=new;</code>
        </td>
        <td style="text-align:left">Permanent: standard</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Date</td>
      <td style="text-align:left">The date and time at which the message was originated (in &quot;HTTP-date&quot;
        format as defined by <a href="http://tools.ietf.org/html/rfc7231#section-7.1.1.1">RFC 7231 Date/Time Formats</a>).</td>
      <td
      style="text-align:left"><code>Date: Tue, 15 Nov 1994 08:12:31 GMT</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Expect</td>
      <td style="text-align:left">Indicates that particular server behaviors are required by the client.</td>
      <td
      style="text-align:left"><code>Expect: 100-continue</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Forwarded</td>
      <td style="text-align:left">Disclose original information of a client connecting to a web server through
        an HTTP proxy.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-15">[15]</a>
      </td>
      <td style="text-align:left"><code>Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43</code>  <code>Forwarded: for=192.0.2.43, for=198.51.100.17</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">From</td>
      <td style="text-align:left">The email address of the user making the request.</td>
      <td style="text-align:left"><code>From: user@example.com</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Host</td>
      <td style="text-align:left">
        <p>The domain name of the server (for <a href="https://en.wikipedia.org/wiki/Virtual_hosting">virtual hosting</a>),
          and the <a href="https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers">TCP port</a> number
          on which the server is listening. The <a href="https://en.wikipedia.org/wiki/Port_(computer_networking)">port</a> number
          may be omitted if the port is the standard port for the service requested.</p>
        <p>Mandatory since HTTP/1.1.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-16">[16]</a> If
          the request is generated directly in HTTP/2, it should not be used.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_Request_Pseudo_Header_Fields-17">[17]</a>
        </p>
      </td>
      <td style="text-align:left">
        <p><code>Host: en.wikipedia.org:8080</code>
        </p>
        <p><code>Host: en.wikipedia.org</code>
        </p>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">HTTP2-Settings</td>
      <td style="text-align:left">A request that upgrades from HTTP/1.1 to HTTP/2 MUST include exactly one <code>HTTP2-Setting</code> header
        field. The <code>HTTP2-Settings</code> header field is a connection-specific
        header field that includes parameters that govern the HTTP/2 connection,
        provided in anticipation of the server accepting the request to upgrade.
        <a
        href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-18">[18]</a><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-19">[19]</a>
      </td>
      <td style="text-align:left"><code>HTTP2-Settings: token64</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">If-Match</td>
      <td style="text-align:left">Only perform the action if the client supplied entity matches the same
        entity on the server. This is mainly for methods like PUT to only update
        a resource if it has not been modified since the user last updated it.</td>
      <td
      style="text-align:left"><code>If-Match: &quot;737060cd8c284d8af7ad3082f209582d&quot;</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">If-Modified-Since</td>
      <td style="text-align:left">Allows a 304 Not Modified to be returned if content is unchanged.</td>
      <td
      style="text-align:left"><code>If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">If-None-Match</td>
      <td style="text-align:left">Allows a 304 Not Modified to be returned if content is unchanged, see
        <a
        href="https://en.wikipedia.org/wiki/HTTP_ETag">HTTP ETag</a>.</td>
      <td style="text-align:left"><code>If-None-Match: &quot;737060cd8c284d8af7ad3082f209582d&quot;</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">If-Range</td>
      <td style="text-align:left">If the entity is unchanged, send me the part(s) that I am missing; otherwise,
        send me the entire new entity.</td>
      <td style="text-align:left"><code>If-Range: &quot;737060cd8c284d8af7ad3082f209582d&quot;</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">If-Unmodified-Since</td>
      <td style="text-align:left">Only send the response if the entity has not been modified since a specific
        time.</td>
      <td style="text-align:left"><code>If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 GMT</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Max-Forwards</td>
      <td style="text-align:left">Limit the number of times the message can be forwarded through proxies
        or gateways.</td>
      <td style="text-align:left"><code>Max-Forwards: 10</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Origin<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-CORS-11">[11]</a>
      </td>
      <td style="text-align:left">Initiates a request for <a href="https://en.wikipedia.org/wiki/Cross-origin_resource_sharing">cross-origin resource sharing</a> (asks
        server for <a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#access-control-response-headers">Access-Control-*</a> response
        fields).</td>
      <td style="text-align:left"><code>Origin: http://www.example-social-network.com</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Pragma</td>
      <td style="text-align:left">Implementation-specific fields that may have various effects anywhere
        along the request-response chain.</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#Avoiding_caching"><code>Pragma: no-cache</code></a>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Prefer</td>
      <td style="text-align:left">Allows client to request that certain behaviors be employed by a server
        while processing a request.</td>
      <td style="text-align:left"><code>Prefer: return=representation</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left">RFC 7240</td>
    </tr>
    <tr>
      <td style="text-align:left">Proxy-Authorization</td>
      <td style="text-align:left">Authorization credentials for connecting to a proxy.</td>
      <td style="text-align:left"><code>Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Range</td>
      <td style="text-align:left">Request only part of an entity. Bytes are numbered from 0. See <a href="https://en.wikipedia.org/wiki/Byte_serving">Byte serving</a>.</td>
      <td
      style="text-align:left"><code>Range: bytes=500-999</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/HTTP_referer">Referer</a> [<a href="https://en.wikipedia.org/wiki/Sic">sic</a>]</td>
      <td
      style="text-align:left">This is the address of the previous web page from which a link to the
        currently requested page was followed. (The word &quot;referrer&quot; has
        been misspelled in the RFC as well as in most implementations to the point
        that it has become standard usage and is considered correct terminology)</td>
        <td
        style="text-align:left"><code>Referer: http://en.wikipedia.org/wiki/Main_Page</code>
          </td>
          <td style="text-align:left">Permanent</td>
          <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">TE</td>
      <td style="text-align:left">
        <p>The transfer encodings the user agent is willing to accept: the same values
          as for the response header field Transfer-Encoding can be used, plus the
          &quot;trailers&quot; value (related to the &quot;<a href="https://en.wikipedia.org/wiki/Chunked_transfer_encoding">chunked</a>&quot;
          transfer method) to notify the server it expects to receive additional
          fields in the trailer after the last, zero-sized, chunk.</p>
        <p>Only <code>trailers</code> is supported in HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>TE: trailers, </code><a href="https://en.wikipedia.org/wiki/Deflate"><code>deflate</code></a>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Trailer</td>
      <td style="text-align:left">The Trailer general field value indicates that the given set of header
        fields is present in the trailer of a message encoded with <a href="https://en.wikipedia.org/wiki/Chunked_transfer_coding">chunked transfer coding</a>.</td>
      <td
      style="text-align:left"><code>Trailer: Max-Forwards</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Transfer-Encoding</td>
      <td style="text-align:left">
        <p>The form of encoding used to safely transfer the entity to the user.
          <a
          href="https://www.iana.org/assignments/http-parameters">Currently defined methods</a>are: <a href="https://en.wikipedia.org/wiki/Chunked_transfer_encoding">chunked</a>,
            compress, deflate, gzip, identity.</p>
        <p>Must not be used with HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Transfer-Encoding: chunked</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Upgrade_header">Upgrade</a>
      </td>
      <td style="text-align:left">
        <p>Ask the server to upgrade to another protocol.</p>
        <p>Must not be used in HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Upgrade: h2c, HTTPS/1.3, IRC/6.9, RTA/x11, websocket</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/User-Agent">User-Agent</a>
      </td>
      <td style="text-align:left">The <a href="https://en.wikipedia.org/wiki/User_agent_string">user agent string</a> of
        the user agent.</td>
      <td style="text-align:left"><code>User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Via</td>
      <td style="text-align:left">Informs the server of proxies through which the request was sent.</td>
      <td
      style="text-align:left"><code>Via: 1.0 fred, 1.1 example.com (Apache/1.1)</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Warning</td>
      <td style="text-align:left">A general warning about possible problems with the entity body.</td>
      <td
      style="text-align:left"><code>Warning: 199 Miscellaneous warning</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>

#### Common non-standard request fields

<table>
  <thead>
    <tr>
      <th style="text-align:left">Field name</th>
      <th style="text-align:left">Description</th>
      <th style="text-align:left">Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Upgrade-Insecure-Requests<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-20">[20]</a>
      </td>
      <td style="text-align:left">
        <p>Tells a server which (presumably in the middle of a HTTP -&gt; HTTPS migration)
          hosts mixed content that the client would prefer redirection to HTTPS and
          can handle <code>Content-Security-Policy: upgrade-insecure-requests</code>
        </p>
        <p>Must not be used with HTTP/2<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Upgrade-Insecure-Requests: 1</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Requested-With</td>
      <td style="text-align:left">Mainly used to identify <a href="https://en.wikipedia.org/wiki/Ajax_(programming)">Ajax</a> requests
        (most <a href="https://en.wikipedia.org/wiki/JavaScript_framework">JavaScript frameworks</a> send
        this field with value of <code>XMLHttpRequest</code>); also identifies Android
        apps using WebView<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-21">[21]</a>
      </td>
      <td style="text-align:left"> <code>X-Requested-With: XMLHttpRequest</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Do_Not_Track">DNT</a><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-22">[22]</a>
      </td>
      <td style="text-align:left">Requests a web application to disable their tracking of a user. This is
        Mozilla&apos;s version of the X-Do-Not-Track header field (since <a href="https://en.wikipedia.org/wiki/Mozilla_Firefox_4">Firefox 4.0</a> Beta
        11). <a href="https://en.wikipedia.org/wiki/Safari_(web_browser)">Safari</a> and
        <a
        href="https://en.wikipedia.org/wiki/Internet_Explorer_9">IE9</a>also have support for this field.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-23">[23]</a> On
          March 7, 2011, a draft proposal was submitted to IETF.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-24">[24]</a> The
          <a
          href="https://en.wikipedia.org/wiki/World_Wide_Web_Consortium">W3C</a>Tracking Protection Working Group is producing a specification.
            <a
            href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-25">[25]</a>
      </td>
      <td style="text-align:left">
        <p><code>DNT: 1</code> (Do Not Track Enabled)</p>
        <p><code>DNT: 0</code> (Do Not Track Disabled)</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/X-Forwarded-For">X-Forwarded-For</a>
        <a
        href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-26">[26]</a>
      </td>
      <td style="text-align:left">A <a href="https://en.wikipedia.org/wiki/De_facto_standard">de facto standard</a> for
        identifying the originating IP address of a client connecting to a web
        server through an HTTP proxy or load balancer. Superseded by Forwarded
        header.</td>
      <td style="text-align:left">
        <p><code>X-Forwarded-For: client1, proxy1, proxy2</code>
        </p>
        <p><code>X-Forwarded-For: 129.78.138.66, 129.78.64.103</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Forwarded-Host<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-27">[27]</a>
      </td>
      <td style="text-align:left">A <a href="https://en.wikipedia.org/wiki/De_facto_standard">de facto standard</a> for
        identifying the original host requested by the client in the <code>Host</code> HTTP
        request header, since the host name and/or port of the reverse proxy (load
        balancer) may differ from the origin server handling the request. Superseded
        by Forwarded header.</td>
      <td style="text-align:left">
        <p><code>X-Forwarded-Host: en.wikipedia.org:8080</code>
        </p>
        <p><code>X-Forwarded-Host: en.wikipedia.org</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Forwarded-Proto<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-28">[28]</a>
      </td>
      <td style="text-align:left">A <a href="https://en.wikipedia.org/wiki/De_facto_standard">de facto standard</a> for
        identifying the originating protocol of an HTTP request, since a reverse
        proxy (or a load balancer) may communicate with a web server using HTTP
        even if the request to the reverse proxy is HTTPS. An alternative form
        of the header (X-ProxyUser-Ip) is used by Google clients talking to Google
        servers. Superseded by Forwarded header.</td>
      <td style="text-align:left"><code>X-Forwarded-Proto: https</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Front-End-Https<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-29">[29]</a>
      </td>
      <td style="text-align:left">Non-standard header field used by Microsoft applications and load-balancers</td>
      <td
      style="text-align:left"><code>Front-End-Https: on</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Http-Method-Override<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-30">[30]</a>
      </td>
      <td style="text-align:left">Requests a web application to override the method specified in the request
        (typically POST) with the method given in the header field (typically PUT
        or DELETE). This can be used when a user agent or firewall prevents PUT
        or DELETE methods from being sent directly (note that this is either a
        bug in the software component, which ought to be fixed, or an intentional
        configuration, in which case bypassing it may be the wrong thing to do).</td>
      <td
      style="text-align:left"><code>X-HTTP-Method-Override: DELETE</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">X-ATT-DeviceId<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-31">[31]</a>
      </td>
      <td style="text-align:left">Allows easier parsing of the MakeModel/Firmware that is usually found
        in the User-Agent String of AT&amp;T Devices</td>
      <td style="text-align:left"><code>X-Att-Deviceid: GT-P7320/P7320XXLPG</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Wap-Profile<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-32">[32]</a>
      </td>
      <td style="text-align:left">Links to an XML file on the Internet with a full description and details
        about the device currently connecting. In the example to the right is an
        XML file for an AT&amp;T Samsung Galaxy S2.</td>
      <td style="text-align:left"><code>x-wap-profile: </code><a href="http://wap.samsungmobile.com/uaprof/SGH-I777.xml"><code>http://wap.samsungmobile.com/uaprof/SGH-I777.xml</code></a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Proxy-Connection<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-33">[33]</a>
      </td>
      <td style="text-align:left">
        <p>Implemented as a misunderstanding of the HTTP specifications. Common because
          of mistakes in implementations of early HTTP versions. Has exactly the
          same functionality as standard Connection field.</p>
        <p>Must not be used with HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Proxy-Connection: keep-alive</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-UIDH<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-34">[34]</a>
        <a
        href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-35">[35]</a><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-36">[36]</a>
      </td>
      <td style="text-align:left">Server-side <a href="https://en.wikipedia.org/wiki/Deep_packet_inspection">deep packet insertion</a> of
        a unique ID identifying customers of <a href="https://en.wikipedia.org/wiki/Verizon_Wireless">Verizon Wireless</a>;
        also known as &quot;perma-cookie&quot; or &quot;supercookie&quot;</td>
      <td
      style="text-align:left"><code>X-UIDH: ...</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Csrf-Token<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-37">[37]</a>
      </td>
      <td style="text-align:left">Used to prevent <a href="https://en.wikipedia.org/wiki/Cross-site_request_forgery">cross-site request forgery</a>.
        Alternative header names are: <code>X-CSRFToken</code><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-38">[38]</a> and <code>X-XSRF-TOKEN</code>
        <a
        href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-39">[39]</a>
      </td>
      <td style="text-align:left"><code>X-Csrf-Token: i8XNjC4b8KVok4uw5RftR38Wgp2BFwql</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p>X-Request-ID,<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-stackoverflow1-40">[40]</a>
          <a
          href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-41">[41]</a>
        </p>
        <p>X-Correlation-ID<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-42">[42]</a>
          <a
          href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-43">[43]</a>
        </p>
      </td>
      <td style="text-align:left">Correlates HTTP requests between a client and server.</td>
      <td style="text-align:left"><code>X-Request-ID: f058ebd6-02f7-4d3f-942e-904344e8cde5</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Save-Data<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-44">[44]</a>
      </td>
      <td style="text-align:left">The Save-Data client hint request header available in Chrome, Opera, and
        Yandex browsers lets developers deliver lighter, faster applications to
        users who opt-in to data saving mode in their browser.</td>
      <td style="text-align:left"><code>Save-Data: on</code>
      </td>
    </tr>
  </tbody>
</table>

### Response fields

#### Standard response fields

<table>
  <thead>
    <tr>
      <th style="text-align:left">Field name</th>
      <th style="text-align:left">Description</th>
      <th style="text-align:left">Example</th>
      <th style="text-align:left">Status</th>
      <th style="text-align:left">Standard</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Accept-CH</td>
      <td style="text-align:left">Requests <a href="https://en.wikipedia.org/wiki/HTTP_Client_Hints">HTTP Client Hints</a>
      </td>
      <td style="text-align:left"><code>Accept-CH: UA, Platform</code>
      </td>
      <td style="text-align:left">Experimental</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc8942">8942</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Access-Control-Allow-Origin,
        <br />Access-Control-Allow-Credentials,
        <br />Access-Control-Expose-Headers,
        <br />Access-Control-Max-Age,
        <br />Access-Control-Allow-Methods,
        <br />Access-Control-Allow-Headers<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-CORS-11">[11]</a>
      </td>
      <td style="text-align:left">Specifying which web sites can participate in <a href="https://en.wikipedia.org/wiki/Cross-origin_resource_sharing">cross-origin resource sharing</a>
      </td>
      <td style="text-align:left"><code>Access-Control-Allow-Origin: *</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Accept-Patch<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-45">[45]</a>
      </td>
      <td style="text-align:left">Specifies which patch document formats this server supports</td>
      <td style="text-align:left"><code>Accept-Patch: text/example;charset=utf-8</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Accept-Ranges</td>
      <td style="text-align:left">What partial content range types this server supports via <a href="https://en.wikipedia.org/wiki/Byte_serving">byte serving</a>
      </td>
      <td style="text-align:left"><code>Accept-Ranges: bytes</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Age</td>
      <td style="text-align:left">The age the object has been in a <a href="https://en.wikipedia.org/wiki/Proxy_cache">proxy cache</a> in
        seconds</td>
      <td style="text-align:left"><code>Age: 12</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Allow</td>
      <td style="text-align:left">Valid methods for a specified resource. To be used for a 405 Method not
        allowed</td>
      <td style="text-align:left"><code>Allow: GET, HEAD</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Alt-Svc<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-46">[46]</a>
      </td>
      <td style="text-align:left">
        <p>A server uses &quot;Alt-Svc&quot; header (meaning Alternative Services)
          to indicate that its resources can also be accessed at a different network
          location (host or port) or using a different protocol</p>
        <p>When using HTTP/2, servers should instead send an ALTSVC frame. <a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-47">[47]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Alt-Svc: http/1.1=&quot;http2.example.com:8001&quot;; ma=7200</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Cache-Control">Cache-Control</a>
      </td>
      <td style="text-align:left">Tells all caching mechanisms from server to client whether they may cache
        this object. It is measured in seconds</td>
      <td style="text-align:left"><code>Cache-Control: max-age=3600</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Connection</td>
      <td style="text-align:left">
        <p>Control options for the current connection and list of hop-by-hop response
          fields.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7230_connection-12">[12]</a>
        </p>
        <p>Must not be used with HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Connection: close</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Disposition<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-48">[48]</a>
      </td>
      <td style="text-align:left">An opportunity to raise a &quot;File Download&quot; dialogue box for a
        known MIME type with binary format or suggest a filename for dynamic content.
        Quotes are necessary with special characters.</td>
      <td style="text-align:left"><code>Content-Disposition: attachment; filename=&quot;fname.ext&quot;</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Encoding</td>
      <td style="text-align:left">The type of encoding used on the data. See <a href="https://en.wikipedia.org/wiki/HTTP_compression">HTTP compression</a>.</td>
      <td
      style="text-align:left"><code>Content-Encoding: gzip</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Language</td>
      <td style="text-align:left">The natural language or languages of the intended audience for the enclosed
        content<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-49">[49]</a>
      </td>
      <td style="text-align:left"><code>Content-Language: da</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Length</td>
      <td style="text-align:left">The length of the response body in <a href="https://en.wikipedia.org/wiki/Octet_(computing)">octets</a> (8-bit
        bytes)</td>
      <td style="text-align:left"><code>Content-Length: 348</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Location</td>
      <td style="text-align:left">An alternate location for the returned data</td>
      <td style="text-align:left"><code>Content-Location: /index.htm</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-MD5</td>
      <td style="text-align:left">A <a href="https://en.wikipedia.org/wiki/Base64">Base64</a>-encoded binary
        <a
        href="https://en.wikipedia.org/wiki/MD5">MD5</a>sum of the content of the response</td>
      <td style="text-align:left"><code>Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==</code>
      </td>
      <td style="text-align:left">Obsolete<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-tools.ietf.org-14">[14]</a>
      </td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Range</td>
      <td style="text-align:left">Where in a full body message this partial message belongs</td>
      <td style="text-align:left"><code>Content-Range: bytes 21010-47021/47022</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Content-Type</td>
      <td style="text-align:left">The <a href="https://en.wikipedia.org/wiki/MIME_type">MIME type</a> of this
        content</td>
      <td style="text-align:left"><code>Content-Type: text/html; charset=utf-8</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Date</td>
      <td style="text-align:left">The date and time that the message was sent (in &quot;HTTP-date&quot;
        format as defined by RFC 7231) <a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-50">[50]</a>
      </td>
      <td style="text-align:left"><code>Date: Tue, 15 Nov 1994 08:12:31 GMT</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Delta-Base</td>
      <td style="text-align:left">Specifies the delta-encoding entity tag of the response.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc3229-10">[10]</a>
      </td>
      <td style="text-align:left"><code>Delta-Base: &quot;abc&quot;</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/HTTP_ETag">ETag</a>
      </td>
      <td style="text-align:left">An identifier for a specific version of a resource, often a <a href="https://en.wikipedia.org/wiki/Message_digest">message digest</a>
      </td>
      <td style="text-align:left"><code>ETag: &quot;737060cd8c284d8af7ad3082f209582d&quot;</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Expires</td>
      <td style="text-align:left">Gives the date/time after which the response is considered stale (in &quot;HTTP-date&quot;
        format as defined by RFC 7231)</td>
      <td style="text-align:left"><code>Expires: Thu, 01 Dec 1994 16:00:00 GMT</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">IM</td>
      <td style="text-align:left">Instance-manipulations applied to the response.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc3229-10">[10]</a>
      </td>
      <td style="text-align:left"><code>IM: feed</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Last-Modified</td>
      <td style="text-align:left">The last modified date for the requested object (in &quot;HTTP-date&quot;
        format as defined by RFC 7231)</td>
      <td style="text-align:left"><code>Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Link</td>
      <td style="text-align:left">Used to express a typed relationship with another resource, where the
        relation type is defined by RFC 5988</td>
      <td style="text-align:left"><code>Link: &lt;/feed&gt;; rel=&quot;alternate&quot;</code><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-google_canonical-51">[51]</a>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/HTTP_location">Location</a>
      </td>
      <td style="text-align:left">Used in <a href="https://en.wikipedia.org/wiki/URL_redirection">redirection</a>,
        or when a new resource has been created.</td>
      <td style="text-align:left">
        <ul>
          <li>Example 1: <code>Location: http://www.w3.org/pub/WWW/People.html</code>
          </li>
          <li>Example 2: <code>Location: /pub/WWW/People.html</code>
          </li>
        </ul>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/P3P">P3P</a>
      </td>
      <td style="text-align:left">This field is supposed to set <a href="https://en.wikipedia.org/wiki/P3P">P3P</a> policy,
        in the form of <code>P3P:CP=&quot;your_compact_policy&quot;</code>. However,
        P3P did not take off,<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-52">[52]</a> most
        browsers have never fully implemented it, a lot of websites set this field
        with fake policy text, that was enough to fool browsers the existence of
        P3P policy and grant permissions for <a href="https://en.wikipedia.org/wiki/Third_party_cookie">third party cookies</a>.</td>
      <td
      style="text-align:left"><code>P3P: CP=&quot;This is not a P3P policy! See https://en.wikipedia.org/wiki/Special:CentralAutoLogin/P3P for more info.&quot;</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Pragma</td>
      <td style="text-align:left">Implementation-specific fields that may have various effects anywhere
        along the request-response chain.</td>
      <td style="text-align:left"><code>Pragma: no-cache</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Preference-Applied</td>
      <td style="text-align:left">Indicates which Prefer tokens were honored by the server and applied to
        the processing of the request.</td>
      <td style="text-align:left"><code>Preference-Applied: return=representation</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left">RFC 7240</td>
    </tr>
    <tr>
      <td style="text-align:left">Proxy-Authenticate</td>
      <td style="text-align:left">Request authentication to access the proxy.</td>
      <td style="text-align:left"><code>Proxy-Authenticate: Basic</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Public-Key-Pins<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-53">[53]</a>
      </td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning">HTTP Public Key Pinning</a>,
        announces hash of website&apos;s authentic <a href="https://en.wikipedia.org/wiki/Transport_Layer_Security">TLS</a> certificate</td>
      <td
      style="text-align:left"><code>Public-Key-Pins: max-age=2592000; pin-sha256=&quot;E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=&quot;;</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Retry-After</td>
      <td style="text-align:left">If an entity is temporarily unavailable, this instructs the client to
        try again later. Value could be a specified period of time (in seconds)
        or a HTTP-date.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-54">[54]</a>
      </td>
      <td style="text-align:left">
        <ul>
          <li>Example 1: <code>Retry-After: 120</code>
          </li>
          <li>Example 2: <code>Retry-After: Fri, 07 Nov 2014 23:59:59 GMT</code>
          </li>
        </ul>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/RFC_(identifier)">RFC</a>  <a href="https://datatracker.ietf.org/doc/html/rfc2616">2616</a>,
        <a
        href="https://datatracker.ietf.org/doc/html/rfc7231">7231</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Server</td>
      <td style="text-align:left">A name for the server</td>
      <td style="text-align:left"><code>Server: Apache/2.4.1 (Unix)</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Set-Cookie</td>
      <td style="text-align:left">An <a href="https://en.wikipedia.org/wiki/HTTP_cookie">HTTP cookie</a>
      </td>
      <td style="text-align:left"><code>Set-Cookie: UserID=JohnDoe; Max-Age=3600; Version=1</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security">Strict-Transport-Security</a>
      </td>
      <td style="text-align:left">A HSTS Policy informing the HTTP client how long to cache the HTTPS only
        policy and whether this applies to subdomains.</td>
      <td style="text-align:left"><code>Strict-Transport-Security: max-age=16070400; includeSubDomains</code>
      </td>
      <td style="text-align:left">Permanent: standard</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Trailer</td>
      <td style="text-align:left">The Trailer general field value indicates that the given set of header
        fields is present in the trailer of a message encoded with <a href="https://en.wikipedia.org/wiki/Chunked_transfer_coding">chunked transfer coding</a>.</td>
      <td
      style="text-align:left"><code>Trailer: Max-Forwards</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Transfer-Encoding</td>
      <td style="text-align:left">
        <p>The form of encoding used to safely transfer the entity to the user.
          <a
          href="https://www.iana.org/assignments/http-parameters">Currently defined methods</a>are: <a href="https://en.wikipedia.org/wiki/Chunked_transfer_encoding">chunked</a>,
            compress, deflate, gzip, identity.</p>
        <p>Must not be used with HTTP/2.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Transfer-Encoding: chunked</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Tk</td>
      <td style="text-align:left">Tracking Status header, value suggested to be sent in response to a DNT(do-not-track),
        possible values:</td>
      <td style="text-align:left"><code>Tk: ?</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Upgrade_header">Upgrade</a>
      </td>
      <td style="text-align:left">
        <p>Ask the client to upgrade to another protocol.</p>
        <p>Must not be used in HTTP/2<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-rfc7540_connection-13">[13]</a>
        </p>
      </td>
      <td style="text-align:left"><code>Upgrade: h2c, HTTPS/1.3, IRC/6.9, RTA/x11, websocket</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Vary</td>
      <td style="text-align:left">Tells downstream proxies how to match future request headers to decide
        whether the cached response can be used rather than requesting a fresh
        one from the origin server.</td>
      <td style="text-align:left">
        <ul>
          <li>Example 1: <code>Vary: *</code>
          </li>
          <li>Example 2: <code>Vary: Accept-Language</code>
          </li>
        </ul>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Via</td>
      <td style="text-align:left">Informs the client of proxies through which the response was sent.</td>
      <td
      style="text-align:left"><code>Via: 1.0 fred, 1.1 example.com (Apache/1.1)</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">Warning</td>
      <td style="text-align:left">A general warning about possible problems with the entity body.</td>
      <td
      style="text-align:left"><code>Warning: 199 Miscellaneous warning</code>
        </td>
        <td style="text-align:left">Permanent</td>
        <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">WWW-Authenticate</td>
      <td style="text-align:left">Indicates the authentication scheme that should be used to access the
        requested entity.</td>
      <td style="text-align:left"><code>WWW-Authenticate: Basic</code>
      </td>
      <td style="text-align:left">Permanent</td>
      <td style="text-align:left"></td>
    </tr>
    <tr>
      <td style="text-align:left">X-Frame-Options<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-55">[55]</a>
      </td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Clickjacking">Clickjacking</a> protection:
        deny - no rendering within a frame, sameorigin - no rendering if origin
        mismatch, allow-from - allow from specified location, allowall - non-standard,
        allow from any location</td>
      <td style="text-align:left"> <code>X-Frame-Options: deny</code>
      </td>
      <td style="text-align:left">Obsolete<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-56">[56]</a>
      </td>
      <td style="text-align:left"></td>
    </tr>
  </tbody>
</table>

#### Common non-standard response fields

<table>
  <thead>
    <tr>
      <th style="text-align:left">Field name</th>
      <th style="text-align:left">Description</th>
      <th style="text-align:left">Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">Content-Security-Policy,
        <br />X-Content-Security-Policy,
        <br />X-WebKit-CSP<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-57">[57]</a>
      </td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Content_Security_Policy">Content Security Policy</a> definition.</td>
      <td
      style="text-align:left"><code>X-WebKit-CSP: default-src &apos;self&apos;</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">Expect-CT<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-58">[58]</a>
      </td>
      <td style="text-align:left">Notify to prefer to enforce <a href="https://en.wikipedia.org/wiki/Certificate_Transparency">Certificate Transparency</a>.</td>
      <td
      style="text-align:left"><code>Expect-CT: max-age=604800, enforce, report-uri=&quot;</code><a href="https://example.example/report"><code>https://example.example/report</code></a><code>&quot;</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">NEL<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-59">[59]</a>
      </td>
      <td style="text-align:left">Used to configure network request logging.</td>
      <td style="text-align:left"><code>NEL: { &quot;report_to&quot;: &quot;name_of_reporting_group&quot;, &quot;max_age&quot;: 12345, &quot;include_subdomains&quot;: false, &quot;success_fraction&quot;: 0.0, &quot;failure_fraction&quot;: 1.0 }</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Permissions-Policy<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-60">[60]</a>
      </td>
      <td style="text-align:left">To allow or disable different features or APIs of the browser.</td>
      <td
      style="text-align:left"><code>Permissions-Policy: fullscreen=(), camera=(), microphone=(), geolocation=(), interest-cohort=()</code>
        <a
        href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-61"><code>[61]</code>
          </a>
          </td>
    </tr>
    <tr>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/HTTP_refresh">Refresh</a>
      </td>
      <td style="text-align:left">Used in redirection, or when a new resource has been created. This refresh
        redirects after 5 seconds. Header extension introduced by Netscape and
        supported by most web browsers. Defined by HTML Standard<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-62">[62]</a>
      </td>
      <td style="text-align:left"><code>Refresh: 5; url=http://www.w3.org/pub/WWW/People.html</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Report-To<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-63">[63]</a>
      </td>
      <td style="text-align:left">Instructs the user agent to store reporting endpoints for an origin.</td>
      <td
      style="text-align:left"><code>Report-To: { &quot;group&quot;: &quot;csp-endpoint&quot;, &quot;max_age&quot;: 10886400, &quot;endpoints&quot;: [ { &quot;url&quot;: &quot;https-url-of-site-which-collects-reports&quot; } ] }</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">Status</td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Common_Gateway_Interface">CGI</a> header
        field specifying the <a href="https://en.wikipedia.org/wiki/HTTP_status">status</a> of
        the HTTP response. Normal HTTP responses use a separate &quot;Status-Line&quot;
        instead, defined by RFC 7230.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-64">[64]</a>
      </td>
      <td style="text-align:left"><code>Status: 200 OK</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">Timing-Allow-Origin</td>
      <td style="text-align:left">The <code>Timing-Allow-Origin</code> response header specifies origins that
        are allowed to see values of attributes retrieved via features of the
        <a
        href="https://developer.mozilla.org/en-US/docs/Web/API/Resource_Timing_API">Resource Timing API</a>, which would otherwise be reported as zero due
          to cross-origin restrictions.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-65">[65]</a>
      </td>
      <td style="text-align:left">
        <p><code>Timing-Allow-Origin: *</code>
        </p>
        <p><code>Timing-Allow-Origin: &lt;origin&gt;[, &lt;origin&gt;]*</code>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Content-Duration<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-66">[66]</a>
      </td>
      <td style="text-align:left">Provide the duration of the audio or video in seconds; only supported
        by Gecko browsers</td>
      <td style="text-align:left"><code>X-Content-Duration: 42.666</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Content-Type-Options<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-67">[67]</a>
      </td>
      <td style="text-align:left">The only defined value, &quot;nosniff&quot;, prevents <a href="https://en.wikipedia.org/wiki/Internet_Explorer">Internet Explorer</a> from
        MIME-sniffing a response away from the declared content-type. This also
        applies to <a href="https://en.wikipedia.org/wiki/Google_Chrome">Google Chrome</a>,
        when downloading extensions.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-68">[68]</a>
      </td>
      <td style="text-align:left"><code>X-Content-Type-Options: nosniff</code><a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-whatwg-fetch-xcto-69">[69]</a>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Powered-By<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-70">[70]</a>
      </td>
      <td style="text-align:left">Specifies the technology (e.g. ASP.NET, PHP, JBoss) supporting the web
        application (version details are often in <code>X-Runtime</code>, <code>X-Version</code>,
        or <code>X-AspNet-Version</code>)</td>
      <td style="text-align:left"><code>X-Powered-By: PHP/5.4.0</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Redirect-By<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-71">[71]</a>
      </td>
      <td style="text-align:left">Specifies the component that is responsible for a particular redirect.</td>
      <td
      style="text-align:left"><code>X-Redirect-By: WordPress</code>
        <br /><code>X-Redirect-By: Polylang</code>
        </td>
    </tr>
    <tr>
      <td style="text-align:left">X-Request-ID,
        <br />X-Correlation-ID<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-stackoverflow1-40">[40]</a>
      </td>
      <td style="text-align:left">Correlates HTTP requests between a client and server.</td>
      <td style="text-align:left"><code>X-Request-ID: f058ebd6-02f7-4d3f-942e-904344e8cde5</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-UA-Compatible<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-72">[72]</a>
      </td>
      <td style="text-align:left">Recommends the preferred rendering engine (often a backward-compatibility
        mode) to use to display the content. Also used to activate <a href="https://en.wikipedia.org/wiki/Chrome_Frame">Chrome Frame</a> in
        Internet Explorer. In HTML Standard, only the <code>IE=edge</code> value
        is defined.<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-73">[73]</a>
      </td>
      <td style="text-align:left"><code>X-UA-Compatible: IE=edge</code>
        <br /><code>X-UA-Compatible: IE=EmulateIE7</code>
        <br /><code>X-UA-Compatible: Chrome=1</code>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">X-XSS-Protection<a href="https://en.wikipedia.org/wiki/List_of_HTTP_header_fields#cite_note-74">[74]</a>
      </td>
      <td style="text-align:left"><a href="https://en.wikipedia.org/wiki/Cross-site_scripting">Cross-site scripting</a> (XSS)
        filter</td>
      <td style="text-align:left"><code>X-XSS-Protection: 1; mode=block</code>
      </td>
    </tr>
  </tbody>
</table>

## HTTP Headers Enumeration

We can enumerate headers with curl, DevTools, BurpSuite or anything that get process headers:

Example with curl:

```text
curl -X GET -s "http://10.10.10.83/" -I
```

