# frozen_string_literal: true
require 'fiddle'
require 'monitor'
require 'securerandom'
require_relative '../hpke_recipient'

module ZrotextCandidate
  # Local provider qualification only. No remote attestation or fallback.
  class ProtectedRecipient
    PREFIX = 'zrotext-managed-ruby-p256-'
    PROVIDER = 'Microsoft Platform Crypto Provider'
    SILENT = 0x40
    P = Fiddle::TYPE_VOIDP
    I = Fiddle::TYPE_INT
    SIGNATURES = {
      'NCryptOpenStorageProvider' => [P,P,I], 'NCryptIsAlgSupported' => [P,P,I],
      'NCryptCreatePersistedKey' => [P,P,P,P,I,I], 'NCryptOpenKey' => [P,P,P,I,I],
      'NCryptGetProperty' => [P,P,P,I,P,I], 'NCryptSetProperty' => [P,P,P,I,I],
      'NCryptFinalizeKey' => [P,I], 'NCryptExportKey' => [P,P,P,P,P,I,P,I],
      'NCryptImportKey' => [P,P,P,P,P,P,I,I], 'NCryptSecretAgreement' => [P,P,P,I],
      'NCryptDeriveKey' => [P,P,P,P,I,P,I], 'NCryptDeleteKey' => [P,I],
      'NCryptFreeObject' => [P]
    }.transform_values(&:freeze).freeze

    def self.probe
      value = new
      value.close
      true
    end

    def self.create(&record_and_flush)
      raise ArgumentError, 'Durable pending receipt callback required' unless record_and_flush
      value = new
      begin
        value.send(:create_key, record_and_flush)
        value
      rescue StandardError => original
        begin
          value.delete_created if value.instance_variable_get(:@created)
        ensure
          value.close
        end
        raise original
      end
    end

    def self.open(alias_name, expected_public)
      raise ArgumentError, 'Alias shape' unless /\Azrotext-managed-ruby-p256-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\z/.match?(alias_name)
      expected = expected_public.b.dup
      HpkeRecipient.point(expected)
      value = new
      begin
        value.send(:open_key, alias_name, expected)
        value
      rescue StandardError
        value.close
        raise
      end
    end

    def alias_name = @alias_name.dup

    def public_point
      @lock.synchronize { need(@qualified && !@closed); public_raw }
    end

    def call(public_point, enc, info, aad, ciphertext)
      @lock.synchronize do
        need(@qualified && !@closed)
        pk, ephemeral, context, authenticated, encrypted = [public_point,enc,info,aad,ciphertext].map { |v| v.b.dup }
        need(context.bytesize <= 36864 && authenticated.bytesize <= 36864 && encrypted.bytesize == 48 && OpenSSL.fixed_length_secure_compare(pk,public_raw))
        agreement_bytes = exchange(ephemeral)
        begin
          HpkeRecipient.open_agreement(agreement_bytes,pk,ephemeral,context,authenticated,encrypted)
        ensure
          agreement_bytes.replace("\x00".b * agreement_bytes.bytesize)
        end
      end
    end

    def delete_created
      @lock.synchronize do
        need(@created && !@closed && @key != 0)
        check(native('NCryptDeleteKey',@key,0))
        @key = 0
        @created = @qualified = false
        close
      end
    end

    def close
      @lock.synchronize do
        return if @closed
        @closed = true
        @qualified = false
        free(@key); @key = 0
        free(@provider); @provider = 0
      end
    end

    private

    def initialize
      @lock = Monitor.new
      @key = @provider = 0
      @closed = @qualified = @created = false
      need(RUBY_PLATFORM.match?(/mingw|mswin/) && Fiddle::SIZEOF_VOIDP == 8)
      # kernel32 is a Windows KnownDLL. Resolve NCrypt through its actual System32 path.
      kernel = Fiddle::Handle.new('kernel32.dll')
      get_directory = Fiddle::Function.new(kernel['GetSystemDirectoryW'],[P,I],I)
      directory = "\x00".b * 65536
      size = get_directory.call(directory,32768)
      need(size > 0 && size < 32768)
      path = directory.byteslice(0,size*2).force_encoding('UTF-16LE').encode('UTF-8')
      @library = Fiddle::Handle.new(path + '\\ncrypt.dll')
      @functions = SIGNATURES.to_h { |name,args| [name,Fiddle::Function.new(@library[name],args,I)] }
      output = handle_buffer
      check(native('NCryptOpenStorageProvider',output,wide(PROVIDER),0))
      @provider = output.unpack1('Q<')
      begin
        need((property(@provider,'Impl Type') & 1) != 0)
        check(native('NCryptIsAlgSupported',@provider,wide('ECDH_P256'),0))
      rescue StandardError
        close
        raise
      end
    end
    private_class_method :new

    def need(value) = (raise ArgumentError,'Protected recipient refused' unless value)
    def wide(value) = (value.encode('UTF-16LE').b + "\x00\x00".b)
    def handle_buffer = [0].pack('Q<')
    def size_buffer = [0].pack('L<')
    def native(name,*args) = (@functions.fetch(name).call(*args) & 0xffffffff)
    def check(status) = (raise ArgumentError,format('Native custody refused (%08x)',status) unless status.zero?)
    def free(handle)
      native('NCryptFreeObject',handle) unless handle.nil? || handle.zero?
    end
    def property(handle,name)
      output = size_buffer; size = size_buffer
      check(native('NCryptGetProperty',handle,wide(name),output,4,size,0))
      need(size.unpack1('L<') == 4)
      output.unpack1('L<')
    end
    def create_key(receipt)
      @alias_name = (PREFIX + SecureRandom.uuid).freeze
      receipt.call(@alias_name)
      output = handle_buffer
      check(native('NCryptCreatePersistedKey',@provider,output,wide('ECDH_P256'),wide(@alias_name),0,SILENT))
      @key = output.unpack1('Q<'); @created = true
      check(native('NCryptSetProperty',@key,wide('Export Policy'),size_buffer,4,0))
      check(native('NCryptFinalizeKey',@key,SILENT))
      qualify
    end
    def open_key(alias_name,expected)
      @alias_name = alias_name.dup.freeze
      output = handle_buffer
      check(native('NCryptOpenKey',@provider,output,wide(alias_name),0,SILENT))
      @key = output.unpack1('Q<')
      qualify
      need(OpenSSL.fixed_length_secure_compare(public_point,expected))
    end
    def public_raw
      need(!@closed && @key != 0)
      blob = "\x00".b * 72; size = size_buffer
      check(native('NCryptExportKey',@key,0,wide('ECCPUBLICBLOB'),0,blob,72,size,SILENT))
      need(size.unpack1('L<') == 72 && blob.unpack('L<2') == [0x314b4345,32])
      point = "\x04".b + blob.byteslice(8,64)
      HpkeRecipient.point(point)
      point
    end
    def qualify
      need(property(@key,'Export Policy').zero?)
      status = native('NCryptExportKey',@key,0,wide('ECCPRIVATEBLOB'),0,0,0,size_buffer,SILENT)
      need([0x80090010,0x8009000a].include?(status))
      point = public_raw
      peer = OpenSSL::PKey::EC.generate('prime256v1')
      expected = peer.derive(HpkeRecipient.point(point))
      actual = exchange(peer.public_key.to_octet_string(:uncompressed))
      need(expected.bytesize == 32 && OpenSSL.fixed_length_secure_compare(expected,actual))
      @qualified = true
    ensure
      expected&.replace("\x00".b * expected.bytesize)
      actual&.replace("\x00".b * actual.bytesize)
    end
    def exchange(peer)
      need(!@closed); HpkeRecipient.point(peer)
      blob = [0x314b4345,32].pack('L<2') + peer.byteslice(1,64)
      imported = handle_buffer; agreement_handle = handle_buffer
      raw = "\x00".b * 32
      begin
        check(native('NCryptImportKey',@provider,0,wide('ECCPUBLICBLOB'),0,imported,blob,72,SILENT))
        check(native('NCryptSecretAgreement',@key,imported.unpack1('Q<'),agreement_handle,SILENT))
        size = size_buffer
        check(native('NCryptDeriveKey',agreement_handle.unpack1('Q<'),wide('TRUNCATE'),0,raw,32,size,0))
        need(size.unpack1('L<') == 32)
        raw.reverse
      ensure
        raw.replace("\x00".b * raw.bytesize)
        free(agreement_handle.unpack1('Q<')); free(imported.unpack1('Q<'))
      end
    end
  end
end
