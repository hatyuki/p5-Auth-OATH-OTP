requires 'perl'                  => '5.008001';
requires 'Class::Accessor::Lite' => '0.04';
requires 'Convert::Base32'       => '0.03';
requires 'Digest::SHA'           => '5.60';
requires 'Math::Int64'           => '0.28';
requires 'parent'                => '0.215';

on 'test' => sub {
    requires 'Test::MockTime' => '0.11';
    requires 'Test::More'     => '0.98';
};
