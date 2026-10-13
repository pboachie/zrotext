# frozen_string_literal: true
require 'json'
require 'digest'

module ZrotextCandidate
  # Pure local content: no save, encryption, approval, or sending authority.
  class TemplateContent
    class Failure < StandardError
      def initialize = super('Invalid template content or preview')
    end
    GSM="@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u00c6\u00e6\u00df\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?\u00a1ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7\u00bfabcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0".freeze
    EXT="\f^{}\\[~]|\u20ac".freeze
    VARIABLE_PATTERN=/\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}/
    def self.key?(key) = key.is_a?(String) && /\A[A-Za-z_][A-Za-z0-9_]{0,31}\z/.match?(key) && !%w[__proto__ prototype constructor].include?(key)
    def self.text(value,maximum)
      raise Failure unless value.is_a?(String)
      owned=value.encode(Encoding::UTF_8);raise Failure unless owned.valid_encoding? && units(owned)<=maximum
      owned.dup.freeze
    rescue StandardError
      raise Failure, cause:nil
    end
    def self.units(text) = text.encode(Encoding::UTF_16LE).bytesize/2
    def initialize(template,values)
      @template=self.class.text(template,4096);raise Failure unless values.is_a?(Hash) && values.size<=32
      stripped=@template.gsub(VARIABLE_PATTERN) { raise Failure unless self.class.key?(Regexp.last_match(1));'' }
      raise Failure if stripped.include?('{') || stripped.include?('}')
      captured=values.dup;raise Failure unless captured.size<=32 && captured.keys.all? { |k| self.class.key?(k) }
      @values={};total=0
      captured.keys.sort.each do |key|
        value=self.class.text(captured.fetch(key),512);total+=key.length+1+self.class.units(value)+(total.positive? ? 1 : 0);raise Failure if total>4096
        @values[key.dup.freeze]=value
      end
      @values.freeze;@canonical=JSON.generate({'v'=>1,'template'=>@template,'values'=>@values}).b.freeze;freeze
    rescue StandardError
      raise Failure, cause:nil
    end
    def self.parse(raw)
      raise Failure unless raw.is_a?(String) && raw.bytesize<=65536
      owned=raw.b.dup;text=owned.dup.force_encoding(Encoding::UTF_8);raise Failure unless text.valid_encoding?
      value=JSON.parse(text,max_nesting:4);raise Failure unless value.is_a?(Hash) && value.keys.sort==%w[template v values] && value['v']==1
      content=new(value['template'],value['values']);raise Failure unless content.canonical==owned
      content
    rescue StandardError
      raise Failure, cause:nil
    end
    def canonical = @canonical.dup
    def digest = Digest::SHA256.hexdigest(@canonical)
    def values = @values.transform_values(&:dup)
    def self.estimate(text)
      text=self.text(text,918);gsm=true;septets=0
      text.each_char do |c|
        raise Failure if c.ord<32 && ![10,13,12].include?(c.ord)
        if EXT.include?(c);septets+=2
        elsif GSM.include?(c);septets+=1
        else;gsm=false;end
      end
      length=gsm ? septets : units(text);per_part=gsm ? (length<=160 ? 160 : 153) : (length<=70 ? 70 : 67);parts=[1,(length+per_part-1)/per_part].max;raise Failure if parts>6
      {encoding:gsm ? 'gsm' : 'ucs2',parts:parts,perPart:per_part,length:length,empty:text.empty?}.freeze
    end
    def preview
      text=+'';offset=0
      @template.to_enum(:scan,VARIABLE_PATTERN).each do
        m=Regexp.last_match;piece=@template[offset...m.begin(0)]+@values.fetch(m[1]);raise Failure if self.class.units(text)+self.class.units(piece)>8192
        text<<piece;offset=m.end(0)
      end
      text<<@template[offset..];raise Failure if self.class.units(text)>8192
      {text:text.freeze,estimate:self.class.estimate(text)}.freeze
    rescue StandardError
      raise Failure, cause:nil
    end
  end
end
