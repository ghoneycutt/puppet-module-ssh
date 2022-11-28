# coding: utf-8

require 'spec_helper'

describe 'Ssh::Permit_root_login' do
  describe 'valid types' do
    [
      'yes',
      'prohibit-password',
      'without-password',
      'forced-commands-only',
      'no',
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
