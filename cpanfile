requires 'perl'                  => '5.008001';
requires 'Class::Accessor::Lite' => '0.04';
requires 'Digest::SHA'           => '5.60';
requires 'Math::Int64'           => '0.28';

on 'test' => sub {
    requires 'Test::More'   => '0.98';
};
