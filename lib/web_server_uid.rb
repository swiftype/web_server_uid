require "base64"
require "ipaddr"
require "web_server_uid/version"

# A WebServerUid represents a UID token, as issued by web browsers like Apache
# (mod_uid, http://www.lexa.ru/programs/mod-uid-eng.html) or nginx (http_userid_module,
# http://nginx.org/en/docs/http/ngx_http_userid_module.html).
#
# (Note that while this is called a "UID", it is almost certainly better understood as a "browser ID", because it is
# unique to each browser and very unlikely to be managed in the same way as any "current user" concept you have.)
#
# UID tokens can be very useful when tracking visitors to your site, and more so than just setting a unique cookie
# from your Rails app, for exactly one reason: since your front-end web server can issue and set the cookie directly,
# it means that you can get the UID logged on the very first request visitors make to your site -- which is often a
# really critical one, since it tells you how they got there in the first place (the HTTP referer) and which page
# they first viewed (the landing page).
#
# So, generally, you'll want to do this:
#
# * Turn on +mod_uid+ or +http_userid_module+.
# * Add the UID to the logs -- in nginx, you'll want to log _both_ +$uid_got+ and +$uid_set+, to handle both the case
#   where you've already seen the browser before and the case where you haven't.
# * In your Rails application,
class WebServerUid
  # This contains all Base64 characters from all possible variants of Base64, according to
  # http://en.wikipedia.org/wiki/Base64 -- this is so that we accept Base64-encoded UID cookies,
  # no matter what their source.
  BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_\\.:!"
  # This is, similarly, all characters that can be used as Base64 padding
  BASE64_PADDING = "=-"
  # This is a Regexp that matches any valid Base64 data
  BASE64_REGEX = Regexp.new("^[#{BASE64_ALPHABET}]+[#{BASE64_PADDING}]*$")

  # How long is the raw binary data required to be (in bytes) after we decode it?
  RAW_BINARY_LENGTH = 16
  # By default, how much extra binary data (in bytes) should we allow?
  DEFAULT_ALLOWED_EXTRA_BINARY_DATA = 1

  class << self
    # Creates a new instance from a hex string; see #initialize for more details. Nicely returns nil if passed nil.
    def from_hex(h, options = { })
      new(h, :hex, options) if h
    end

    # Creates a new instance from a binary string; see #initialize for more details. Nicely returns nil if passed nil.
    def from_binary(b, options = { })
      new(b, :binary, options) if b
    end

    # Creates a new instance from a base64 string; see #initialize for more details. Nicely returns nil if passed nil.
    def from_base64(b, options = { })
      new(b, :base64, options) if b
    end

    # Given a string like "st_brid=0100007FE7D7F35241946D1E02030303", and the expected name of the ID cookie
    # (_e.g._, +st_brid+), returns a WebServerUid if one is found, and nil otherwise. Also returns nil if input is nil.
    # This is the exact format you get in a request.env header if you have lines like these in your nginx config:
    #
    #     proxy_set_header X-Nginx-Browser-ID-Got $uid_got;
    #     proxy_set_header X-Nginx-Browser-ID-Set $uid_set;
    #
    # This is just a simple little method to make your parsing a bit easier.
    def from_header(s, expected_name)
      if s && s =~ /#{expected_name}\s*\=\s*([0-9A-F]{32})/i
        from_hex($1)
      end
    end

    # Generates a brand-new instance, from scratch. This follows exactly the algorithm in nginx-1.5.10:
    #
    # * The first four bytes are the local IP address (entire if IPv4, four LSB if IPv6);
    # * The next four bytes are the current time, as a Unix epoch time;
    # * The next two bytes are a function of the start time of the process, but LSBs in microseconds;
    # * The next two bytes are the PID of the process;
    # * The next three bytes are a sequence value, starting at 0x030303;
    # * The last byte is 2, for version 2.
    #
    # +options+ can contain:
    #
    # [:ip_address] Must be an IPAddr object to use as the IP address of this machine, in lieu of autodetection
    #               (see #find_local_ip_address, below).
    def generate(options = { })
      # Yes, global variables. What what?
      #
      # Well, in certain cases (like under Rails), this class may get unloaded and reloaded. (Yes, it's in a gem, so
      # theoretically this shouldn't happen, but we want to be really, really careful.) Because we need to be really
      # sure to maintain uniqueness, we use global variables, which, unlike class variables, won't get reset if this
      # class gets loaded or unloaded
      $_web_server_uid_start_value ||= ((Time.now.usec / 20) << 16) | (Process.pid & 0xFFFF)
      $_web_server_uid_sequencer ||= 0x030302
      $_web_server_uid_sequencer += 1
      $_web_server_uid_sequencer &= 0xFFFFFF

      extra = options.keys - [ :ip_address ]
      if extra.length > 0
        raise ArgumentError, "Unknown keys: #{extra.inspect}"
      end

      ip_address = if options[:ip_address]
        IPAddr.new(options[:ip_address])
      else
        find_local_ip_address
      end

      components = [
        ip_address.to_i & 0xFFFFFFFF,
        Time.now.to_i,
        $_web_server_uid_start_value,
        ($_web_server_uid_sequencer << 8) | 0x2
      ]

      binary = components.pack("NNNN")
      from_binary(binary)
    end

    private
    # Finds the local IP address. This looks like evil voodoo, but it isn't -- no actual network traffic or connection
    # is made. 8.8.8.8 is, famously, one of Google's DNS servers; this tells Ruby to open a UDP socket bound to it --
    # but, unlike TCP, opening a UDP socket doesn't actually do anything until you send something on it. The clever bit
    # is that this will magically find whatever interface your machine would send traffic to Google on, which almost
    # everybody is going to have (even if it's firewalled off somewhere out there on the network), and return the IP
    # address of that.
    #
    # Note that this could be an IPv6 address. This works properly; we grab the four LSB, above.
    #
    # (Much credit to http://coderrr.wordpress.com/2008/05/28/get-your-local-ip-address/.)
    def find_local_ip_address
      @local_ip_address ||= begin
        require 'socket'
        ipaddr_string = UDPSocket.open {|s| s.connect('8.8.8.8', 1); s.addr.last }
        IPAddr.new(ipaddr_string)
      end
    end
  end

  # Creates a new WebServerUid object. +raw_data+ must be a String, in one of the following formats:
  #
  # * Hex-encoded -- the format nginx renders them in logs; _e.g._, <tt>0100007FE7D7F35241946D1E02030303</tt>.
  #   This is a hex encoding of four *little-endian* four-byte integers underneath.
  # * Base64.encoded -- the format of the actual cookie in client browsers; _e.g._, <tt>fwAAAVLz1+cebZRBAwMDAgS=</tt>.
  #   This is a Base64 encoding of four *big-endian* four-byte integers.
  # * Raw binary -- the hex-decoded or Base64-decoded version of above; _e.g._, <tt>\x01\x00\x00\x7F\xE7\xD7\xF3RA\x94m\x1E\x02\x03\x03\x03</tt>.
  #   This is expected to be four *big-endian* four-byte integers.
  #
  # ...and +type+ must be the corresponding format -- one of :binary, :hex, or :base64. (It is not possible to guess
  # the format 100% reliably from the inbound +raw_data+, since raw binary can happen to look like one of the others.)
  #
  # +options+ can contain:
  #
  # [:max_allowed_extra_binary_data] If more data is present in the input string than is necessary for the UID to
  #                                  be parsed, this determines how much extra is allowed before an exception is raised;
  #                                  this defaults to 1, since, if you use nginx's +userid_mark+ directive, you'll
  #                                  get exactly that character in the Base64 at the end, and this will translate to
  #                                  extra data.
  def initialize(raw_data, type, options = { })
    raise ArgumentError, "Type must be one of :binary, :hex, or :base64, not #{type.inspect}" unless [ :binary, :hex, :base64 ].include?(type)
    @input_type = type

    @binary_components = case type
    when :hex then
      @raw_binary_data = [ raw_data ].pack("H*")
      @raw_binary_data.unpack("VVVV")
    when :base64 then
      @raw_binary_data = Base64.decode64(raw_data)
      @raw_binary_data.unpack("NNNN")
    when :binary then
      @raw_binary_data = raw_data
      @raw_binary_data.unpack("NNNN")
    else
      raise "wrong type: #{type.inspect}; need to add support for it?"
    end

    @extra_binary_data = @raw_binary_data[RAW_BINARY_LENGTH..-1]
    @raw_binary_data = @raw_binary_data[0..(RAW_BINARY_LENGTH - 1)]

    if @raw_binary_data.length < RAW_BINARY_LENGTH
      raise ArgumentError, "This UID cookie does not appear to be long enough; its raw binary data is of length #{@raw_binary_data.length}, which is less than #{RAW_BINARY_LENGTH.inspect}: #{raw_data.inspect} (became #{@raw_binary_data.inspect})"
    end

    if @extra_binary_data.length > (options[:max_allowed_extra_binary_data] || DEFAULT_ALLOWED_EXTRA_BINARY_DATA)
      raise ArgumentError, "This UID cookie has #{@extra_binary_data.length} bytes of extra binary data at the end: #{@raw_binary_data.inspect} adds #{@extra_binary_data.inspect}"
    end
  end

  # This, plus Comparable, implements all the equality and comparison operators we could ever need.
  def <=>(other)
    other_components = other.binary_components
    binary_components.each_with_index do |our_component, index|
      other_component = other_components[index]
      out = our_component <=> other_component
      return out unless out == 0
    end
    0
  end

  include Comparable

  # ...well, except for this one. ;)
  def eql?(other)
    self == other
  end

  # Let's make sure we hash ourselves correctly, so we, well, work inside a Hash. :)
  def hash
    binary_components.hash
  end

  # Returns the hex-encoded variant of the UID -- exactly the string that nginx logs to disk or puts in
  # a header created with $uid_got, etc.
  #
  # This will be identical for two equivalent UIDs, no matter what representations they were parsed from.
  def to_hex_string
    @binary_components.pack("VVVV").bytes.map { |b| "%02X" % b }.join("")
  end

  # Returns the Base64-encoded variant of the UID -- exactly the string that ends up in a cookie in client browsers.
  #
  # This will be identical for two equivalent UIDs, no matter what representations they were parsed from.
  def to_base64_string
    Base64.encode64(@binary_components.pack("NNNN"))
  end

  # Returns a pure-binary string for this UID.
  #
  # This will be identical for two equivalent UIDs, no matter what representations they were parsed from.
  def to_binary_string
    @binary_components.pack("NNNN")
  end

  # Returns an Array of length 4; each component will be a single, four-byte Integer, in big-endian byte order,
  # representing the underlying UID.
  def binary_components
    @binary_components
  end

  # Returns any extra binary data that was supplied (and successfully ignored) past the end of the input string.
  def extra_binary_data
    @extra_binary_data
  end

  # This is the "service number" -- the first byte of the UID string. Typically, this is the IP address of the
  # server that generated the UID.
  def service_number
    @binary_components[0]
  end

  # Returns the "service number" as an IPAddr object; you can call #to_s on this to get a string in dotted notation.
  def service_number_as_ip
    IPAddr.new(service_number, Socket::AF_INET)
  end

  # This is the "issue time" -- the time at which the UID was generated, as a Un*x epoch time -- as an integer.
  def issue_time
    @binary_components[1]
  end

  # This is the issue time, as a Time object.
  def issue_time_as_time
    Time.at(issue_time)
  end

  # This is the "process ID" component -- the third four bytes. While this is documented as simply being the process ID
  # of the server process, realistically, servers add more entropy to avoid collisions (and because PIDs are often
  # only two bytes long). Nginx sets the top two bytes to the two least-significant bytes of the current time in
  # microseconds, for example. So we have #pid_component, here, that returns the whole thing, and #pid that returns
  # just the actual PID.
  def pid_component
    @binary_components[2]
  end

  # As explained above, this is just the PID itself from the third comppnent.
  def pid
    pid_component & 0xFFFF
  end

  # This is the "sequencer" component -- the last four bytes, which contains both a cookie version number (the LSB)
  # and a sequence number (the three MSBs).
  def sequencer_component
    @binary_components[3]
  end

  # The actual sequencer value.
  def sequencer
    sequencer_component >> 8
  end

  # The sequencer value, as a six-byte hex string, which is a much easier way of looking at it (since it's oddly
  # defined to start at 0x030303.)
  def sequencer_as_hex
    "%06x" % sequencer
  end

  # The version number of the cookie -- the LSB of the sequencer_component.
  def cookie_version_number
    @binary_components[3] & 0xFF
  end
end
