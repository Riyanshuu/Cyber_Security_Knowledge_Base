## HTTP Status Codes

When accessing a web server or application, every HTTP request that is receives by a server is responded to with an HTTP status code. 

HTTP status codes are three-digit codes, and are grouped into five different classes.

The class of a status code can be identified by its first digit:

- 1xx: Informational
- 2xx: Success
- 3xx: Redirection
- 4xx: Client Error
- 5xx: Server Error

![1655606107744](https://user-images.githubusercontent.com/68123282/176370430-0e44b864-c0c5-4b33-aaef-1c756b5df753.jpg)

**202 Accepted Response**

It indicates that the request has been accepted for processing, but the processing has not been completed.

**302 Found Redirect**

It indicates that the resource requested has been temporarily moved to a specific URL given by the Location header.

The most commonly encountered HTTP error codes are 4xx (client error) and 5xx (server error).

### Client Errors (400 - 499)

Client Errors are the result of HTTP requests sent by a user client (web browser or other HTTP client).

**400 Bad Request** 

The 400 status code, or *Bad Request* ****error, means the HTTP request that was set to the server has invalid syntax.

Here are a few examples of when a 400 Bad Request error might occur:

- The user’s cookie that is associated with the site is corrupt. Clearing the browser’s cache and cookies could solve this issue
- Malformed request due to a faulty browser
- Malformed request due to human error when manually forming HTTP requests (e.g. using `curl` incorrectly)

**401 Unauthorized**

The 401 status code, or an *Unauthorized* error, means that the user trying to access the resource has not been authenticated or has not been authenticated correctly. 

This means that the user must provide credentials to be able to view the protected resources.

**402 Payment Required**

It is a nonstandard response status code that is reserved for future use. This status code was created to enable digital cash or payment systems and would indicate that the requested content is not available until the client makes a payment.

**403 Forbidden**

The 403 status code, or a *Forbidden* error, means that the user made a valid request but the server is refusing to serve the request, due to lack of permission to access the requested resource. If you are encountering a 403 error unexpectedly, there are a few typical causes that are:

- File permissions
- `.htaccess` - The `.htaccess` file can be used to deny access of certain resources to specific IP addresses or ranges.
- Index file does not exist.

**404 Not Found**

The 404 status code, or a *Not Found* error, means that the user is able to communicate with the server but it is unable to locate the requested file or resource.

404 errors can occur in a large variety of situations. If the user is unexpectedly receiving a 404 Not Found error, here are some questions to ask while troubleshooting:

- Does the link that directed the user to your server resource have a typographical error in it?
- Did the user type in the wrong URL?
- Does the file exist in the correct location on the server? Was the resource was moved or deleted on the server?
- Does the server configuration have the correct document root location?
- Does the user that owns the web server worker process have privileges to traverse to the directory that the requested file is in? (Hint: directories require read and execute permissions to be accessed)
- Is the resource being accessed a symbolic link? If so, ensure the web server is configured to follow symbolic links

### Server Errors (500 - 599)

Server errors are returned by a web server when it is aware that an error has occurred or is otherwise not able to process the request.

**500 Internal Server Error**

The 500 status code, or *Internal Server* error, means that server cannot process the request for an unknown reason. Sometimes this code will appear when more specific 5xx errors are more appropriate.

The most common cause for this error is server misconfiguration (e.g. a malformed `.htaccess` file) or missing packages (e.g. trying to execute a PHP file without PHP installed properly).

**501 Not Implemented**

The 501 status code, or *Not Implemented* error, means that the server does not support the functionality required to fulfill the request.

**502 Bad Gateway**

The 502 status code, or *Bad Gateway* error, means that the server is a gateway or proxy server, and it is not receiving a valid response from the backend servers that should actually fulfill the request.

If the server in question is a reverse proxy server, such as a load balancer, here are a few things to check:

- The backend servers (where the HTTP requests are being forwarded to) are healthy
- The reverse proxy is configured properly, with the proper backends specified
- The network connection between the backend servers and reverse proxy server is healthy. If the servers can communicate on other ports, make sure that the firewall is allowing the traffic between them
- If your web application is configured to listen on a socket, ensure that the socket exists in the correct location and that it has the proper permissions

**503 Service Unavailable**

The 503 status code, or *Service Unavailable* error, means that the server is overloaded or under maintenance. This error implies that the service should become available at some point.

If the server is not under maintenance, this can indicate that the server does not have enough CPU or memory resources to handle all of the incoming requests, or that the web server needs to be configured to allow more users, threads, or processes.

**504 Gateway Timeout**

The 504 status code, or *Gateway Timeout* error, means that the server is a gateway or proxy server, and it is not receiving a response from the backend servers within the allowed time period.

This typically occurs in the following situations:

- The network connection between the servers is poor
- The backend server that is fulfilling the request is too slow, due to poor performance
- The gateway or proxy server’s timeout duration is too short
