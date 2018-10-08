# coding: utf-8

require 'spec_helper'

describe 'Ssh::Syslog_facility' do
  describe 'valid types' do
    [
      'DAEMON',
      'USER',
      'AUTH',
      'LOCAL0',
      'LOCAL1',
      'LOCAL2',
      'LOCAL3',
      'LOCAL4',
      'LOCAL5',
      'LOCAL6',
      'LOCAL7',
      'AUTHPRIV',
    ].each do |value|
      describe value.inspect do
        it { is_expected.to allow_value(value) }
      end
    end
  end

  describe 'invalid types' do
    context 'with garbage inputs' do
      [
        true,
        false,
        :keyword,
        nil,
        ['yes', 'no'],
        { 'foo' => 'bar' },
        {},
        '',
        'ネット',
        '55555',
        '0x123',
        'daemon',
        'local',
        'AUTH0',
      ].each do |value|
        describe value.inspect do
          it { is_expected.not_to allow_value(value) }
        end
      end
    end
  end
end
