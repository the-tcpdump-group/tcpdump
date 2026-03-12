## DNS requests

DNS requests are formatted as:
 
>     src > dst: id op? flags qtype qclass name (len)

For example, let's break down this line:

>     192.0.2.1.1234 > 8.8.8.8.53: 492+ [1au] A? example.com. (36)

The most commonly used fields here are:

* **Source IP and port**: \`192.0.2.1.1234'
* **Destination IP and port**: \`8.8.8.8.53'
* **DNS query type**: \`A'. The query type is right before the \`?'
* **Domain name** being looked up: \`example.com.'

All the other fields, in the order they appear:

* **Query ID**: \`492'
* **Opcode**: The opcode was the normal one, *Query*, so it was omitted.
  Any other opcode would have been printed between the \`492' and
  the \`+', for example \`492 update+'
* **Flags**: \`+' means the "recursion desired" flag was set
* **Records in the query**: \`[1au]' means that the query contains 1 record in the "additional" section. In general:
   * \`\[*n*a\]' means "*n* answer records"
   * \`\[*n*n\]' means "*n* authority records"
   * \`\[*n*au\]' means "*n* additional records"
* **Class**: The query class was the normal one, *C_IN*, so it was omitted.
  Any other query class would have been printed immediately after the \`A'
* **Other anomalies**: If any of the response bits are set (AA, RA, TC or response code)
  or any of the "must be zero" bits are set in bytes two and three,
  \`\[b2&3=*x*\]' is printed, where *x* is the hex value of header bytes
  two and three.
* **Query length**: 36 bytes (excluding the TCP or UDP and IP protocol headers)

## DNS Responses

DNS responses are formatted as
 
>     src > dst:  id op rcode flags a/n/au type class data (len)
 
Here are 2 example responses we'll break down:

>     #1: IP 8.8.8.8.53 > 192.0.2.1.1234: 492 2/0/1 A 104.18.27.120, A 104.18.26.120 (72)
>     #2: IP 8.8.8.8.53 > 192.0.2.1.1234: 492 NXDomain 0/0/1 (46)

The most commonly used fields here are:

* **Source IP and port**: `192.0.2.1.1234`
* **Destination IP and port**: `8.8.8.8.53`
* **The records**: In example 1, the server replied with two A records: \`A 104.18.27.120' and \`A 104.18.26.120'
* **DNS response code**: In example 2, the response code is "NXDomain", which means the domain wasn't found
 
All the other fields, in the order they appear:

* **Query ID**: 492  
* **Opcode**: Same as for DNS requests above. Omitted here.
* **Flags**: Flags are after the query ID and opcode (for example `492 update|`), and are encoded like this:
  * RA: '-' if RA is missing ("Recursion Available")
  * TC: '|' ("Truncated")
  * AA: '*' ("Authoritative Answer")
  * AD: '$' ("Authenticated Data")
* **Question records**: If the \`question' section doesn't contain
    exactly one entry, \`\[*n*q\]' is printed.
* **Total number of records**: `2/0/1`: This means 2 _answer records_, 0 _authority records_, and 1 _additional record_ (from example 1)
* **Class**: Same as for DNS requests above. Omitted here.
* **Length**: Same as for DNS requests above.
