# coding: utf-8

require 'spec_helper'

describe 'Ssh::Key::Type' do
  describe 'valid types' do
    [
      'ssh-dss',
      'ssh-ed25519',
      'ssh-rsa',
      'ecdsa-sha2-nistp256',
      'ecdsa-sha2-nistp384',
      'ecdsa-sha2-nistp521',
      'ed25519',
      'rsa',
      'dsa',
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
        [nil],
        [nil, nil],
        { 'foo' => 'bar' },
        {},
        '',
        'ネット',
        '55555',
        '0x123',
        'ssh-dssss',
        'xrsa',
      ].each do |value|
        describe value.inspect do
          it { is_expected.not_to allow_value(value) }
        end
      end
    end
  end
end
