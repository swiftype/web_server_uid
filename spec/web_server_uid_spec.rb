require 'web_server_uid'

describe WebServerUid do
  describe "class methods" do
    it "should return nil if given nil" do
      expect(WebServerUid.from_hex(nil)).to be_nil
      expect(WebServerUid.from_binary(nil)).to be_nil
      expect(WebServerUid.from_base64(nil)).to be_nil
    end

    it "should return a value if given one" do
      expect(WebServerUid.from_hex("0100007FE7D7F35241946D1E02030303").to_hex_string).to eq("0100007FE7D7F35241946D1E02030303")
      expect(WebServerUid.from_binary("\177\000\000\001R\363\327\347\036m\224A\003\003\003\002").to_hex_string).to eq("0100007FE7D7F35241946D1E02030303")
      expect(WebServerUid.from_base64("fwAAAVLz1+cebZRBAwMDAgS=").to_hex_string).to eq("0100007FE7D7F35241946D1E02030303")
    end

    it "should be able to parse a value from a header" do
      expect(WebServerUid.from_header("st_brid=0100007FE7D7F35241946D1E02030303", "st_brid").to_hex_string).to eq("0100007FE7D7F35241946D1E02030303")
      expect(WebServerUid.from_header("baz=0100007FE7D7F35241946D1E02030303", "st_brid")).to be_nil
      expect(WebServerUid.from_header("st_brid=0100007FE7D7F35241946D1E0203030Q", "st_brid")).to be_nil
      expect(WebServerUid.from_header("st_brid=0100007FE7D7F35241946D1E020303", "st_brid")).to be_nil
    end
  end

  describe "generating a brand-new instance" do
    before :each do
      @generated = WebServerUid.generate
    end

    it "should be able to create a new instance" do
      expect(@generated).to be_instance_of(WebServerUid)
    end

    it "should have the right time" do
      expect((Time.now.to_i - @generated.issue_time.to_i).abs).to be < 300
    end

    it "should have the right IP" do
      require 'socket'
      expected_ipaddr_string = UDPSocket.open {|s| s.connect('8.8.8.8', 1); s.addr.last }
      expected_ipaddr = IPAddr.new(expected_ipaddr_string)

      expect(@generated.service_number_as_ip).to eq(expected_ipaddr)
    end

    it "should let you override the IP" do
      @generated = WebServerUid.generate(:ip_address => "127.0.0.1")
      expect(@generated.to_hex_string).to match(/^0100007F/)
    end

    it "should fail if passed unknown options" do
      expect { WebServerUid.generate(:foo => :bar) }.to raise_error(ArgumentError)
    end

    it "should fail if passed something that isn't an IP address" do
      expect { WebServerUid.generate(:ip_address => /foobar/) }.to raise_error(ArgumentError)
    end

    it "should have the right PID" do
      expect(@generated.pid).to eq(Process.pid)
    end

    it "should have the right sequencer" do
      expect(@generated.sequencer).to be >= 0x030303
      expect(@generated.sequencer).to be <= (0x030303 + 50)
    end

    it "should have the right version" do
      expect(@generated.cookie_version_number).to eq(2)
    end

    it "should never generate the same ID twice" do
      ids = [ ]
      1000.times { ids << WebServerUid.generate }
      expect(ids.map(&:to_hex_string).uniq.length).to eq(1000)
    end

    it "should turn itself into a string reasonably, and say where it's from" do
      expect(@generated.to_s).to match(/generated/i)
      expect(@generated.to_s).to match(/#{@generated.to_hex_string}/i)
    end

    it "should inspect itself reasonably, and say where it's from" do
      expect(@generated.inspect).to match(/generated/i)
      expect(@generated.inspect).to match(/#{@generated.to_hex_string}/i)
    end
  end

  describe "known examples" do
    { :hex => '0100007FE7D7F35241946D1E02030303', :base64 => 'fwAAAVLz1+cebZRBAwMDAgS=',
      :binary => "\177\000\000\001R\363\327\347\036m\224A\003\003\003\002" }.each do |type, raw|
      describe type.to_s do
        let(:raw) { @raw }
        let(:uid) { WebServerUid.new(raw, type) }

        it "should have the right hex string" do
          expect(uid.to_hex_string).to eq('0100007FE7D7F35241946D1E02030303')
        end

        it "should have the right Base64 string" do
          expect(uid.to_base64_string).to eq("fwAAAVLz1+cebZRBAwMDAg==\n")
        end

        it "should have the right binary string" do
          actual = uid.to_binary_string
          actual.force_encoding(Encoding::BINARY) if actual.respond_to?(:force_encoding)
          expected = "\177\000\000\001R\363\327\347\036m\224A\003\003\003\002"
          expected.force_encoding(Encoding::BINARY) if expected.respond_to?(:force_encoding)

          expect(actual).to eq(expected)
          if uid.to_binary_string.respond_to?(:encoding)
            expect(uid.to_binary_string.encoding).to eq(Encoding::BINARY)
          end
        end

        it "should have the right binary components" do
          expect(uid.binary_components).to eq([ 2130706433, 1391712231, 510497857, 50529026 ])
        end

        it "should have the right extra binary data" do
          if type == :base64
            expect(uid.extra_binary_data).to eq("\004")
          else
            expect(uid.extra_binary_data).to eq("")
          end
        end

        it "should have the right service number" do
          expect(uid.service_number).to eq(2130706433)
        end

        it "should have the right server IP" do
          expect(uid.service_number_as_ip).to eq(IPAddr.new('127.0.0.1'))
        end

        it "should have the right issue time" do
          expect(uid.issue_time).to eq(1391712231)
        end

        it "should have the right issue time as time" do
          expect(uid.issue_time_as_time).to eq(Time.parse('Thu Feb 06 10:43:51 -0800 2014'))
        end

        it "should have the right PID component" do
          expect(uid.pid_component).to eq(510497857)
        end

        it "should have the right PID" do
          expect(uid.pid).to eq(37953)
        end

        it "should have the right sequencer component" do
          expect(uid.sequencer_component).to eq(50529026)
        end

        it "should have the right sequencer value" do
          expect(uid.sequencer).to eq(197379)
        end

        it "should have the right sequencer, as hex" do
          expect(uid.sequencer_as_hex).to eq("030303")
        end

        it "should have the right cookie version number" do
          expect(uid.cookie_version_number).to eq(2)
        end

        it "should turn itself into a string reasonably, and say where it's from" do
          expect(uid.to_s).to match(/#{uid.to_hex_string}/i)
          expect(uid.to_s).to match(/#{type}/i)
        end

        it "should inspect itself reasonably, and say where it's from" do
          expect(uid.inspect).to match(/#{uid.to_hex_string}/i)
          expect(uid.inspect).to match(/#{type}/i)
        end
      end
    end
  end

  describe "comparison and hashing" do
    let(:example_1) { WebServerUid.from_hex('0100007FE7D7F35241946D1E02030303') }
    let(:example_2) { WebServerUid.from_hex('0100007FE7D7F35241946D1E02030304') }
    let(:example_3) { WebServerUid.from_hex('0100007FE7D7F35241946D1E02030303') }
    let(:example_4) { WebServerUid.from_hex('0100006FE7D7F35241946D1E02030303') }

    it "should compare itself with <=> correctly" do
      expect(example_1 <=> example_2).to be < 0
      expect(example_1 <=> example_3).to eq(0)
      expect(example_1 <=> example_4).to be > 0
      expect(example_2 <=> example_3).to be > 0
      expect(example_2 <=> example_4).to be > 0
      expect(example_3 <=> example_4).to be > 0

      expect(example_2 <=> example_1).to be > 0
      expect(example_3 <=> example_1).to eq(0)
      expect(example_4 <=> example_1).to be < 0
      expect(example_3 <=> example_2).to be < 0
      expect(example_4 <=> example_2).to be < 0
      expect(example_4 <=> example_3).to be < 0

      expect(example_1.eql?(example_1)).to be_true
      expect(example_1.eql?(example_3)).to be_true
      expect(example_3.eql?(example_1)).to be_true
      expect(example_1.eql?(example_2)).to_not be_true
      expect(example_2.eql?(example_1)).to_not be_true
    end

    it "should hash itself correctly" do
      expect(example_1.hash).to eq(example_1.hash)
      expect(example_1.hash).to eq(example_3.hash)
      expect(example_2.hash).to eq(example_2.hash)
      expect(example_3.hash).to eq(example_3.hash)
      expect(example_4.hash).to eq(example_4.hash)
    end
  end

  (0..99).each do |index|
    describe "random example #{index}" do
      before :each do
        @service_number = rand(2**32)
        @issue_time = rand(2**31)
        @issue_time_as_time = Time.at(@issue_time)
        @pid_high = rand(2**16)
        @pid = rand(2**16)
        @sequencer = rand(2**24)
        @version = rand(256)
        @extra = rand(2) == 0 || true ? (65 + rand(26)).chr : ''

        @components = [
          @service_number,
          @issue_time,
          (@pid_high << 16) | @pid,
          (@sequencer << 8) | @version
        ]

        @binary = @components.pack("NNNN")
        @hex = @components.pack("VVVV").bytes.map { |b| "%02X" % b}.join("")
        @base64_base = Base64.encode64(@components.pack("NNNN"))
        @base64 = begin
          out = @base64_base.dup
          if @extra.length > 0
            if out =~ /^(.*?)(=*)$/
              out = "#{$1}#{@extra}#{$2}"
            end
          end
          out
        end
      end

      [ :hex, :base64, :binary ].each do |type|
        describe type.to_s do
          before :each do
            @raw = instance_variable_get("@#{type}")
            @uid = WebServerUid.new(@raw, type)
          end

          it "should have the right hex string" do
            expect(@uid.to_hex_string).to eq(@hex)
          end

          it "should have the right Base64 string" do
            expect(@uid.to_base64_string).to eq(@base64_base)
          end

          it "should have the right binary string" do
            expect(@uid.to_binary_string).to eq(@binary)
            if @uid.to_binary_string.respond_to?(:encoding)
              expect(@uid.to_binary_string.encoding).to eq(Encoding::BINARY)
            end
          end

          it "should have the right binary components" do
            expect(@uid.binary_components).to eq(@components)
          end

          it "should have the right extra binary data" do
            if type == :base64 && @extra.length > 0
              actual_extra = Base64.decode64(@base64)[16..-1]
              expect(@uid.extra_binary_data).to eq(actual_extra)
            else
              expect(@uid.extra_binary_data).to eq("")
            end
          end

          it "should have the right service number" do
            expect(@uid.service_number).to eq(@service_number)
          end

          it "should have the right server IP" do
            expect(@uid.service_number_as_ip).to eq(IPAddr.new(@service_number, Socket::AF_INET))
          end

          it "should have the right issue time" do
            expect(@uid.issue_time).to eq(@issue_time)
          end

          it "should have the right issue time as time" do
            expect(@uid.issue_time_as_time).to eq(@issue_time_as_time)
          end

          it "should have the right PID component" do
            expect(@uid.pid_component).to eq(@components[2])
          end

          it "should have the right PID" do
            expect(@uid.pid).to eq(@pid)
          end

          it "should have the right sequencer component" do
            expect(@uid.sequencer_component).to eq(@components[3])
          end

          it "should have the right sequencer value" do
            expect(@uid.sequencer).to eq(@sequencer)
          end

          it "should have the right sequencer, as hex" do
            expect(@uid.sequencer_as_hex).to eq("%06x" % @sequencer)
          end

          it "should have the right cookie version number" do
            expect(@uid.cookie_version_number).to eq(@version)
          end
        end
      end
    end
  end
end
