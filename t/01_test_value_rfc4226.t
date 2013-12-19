use strict;
use warnings;
use Test::More;
use Auth::OATH::OTP;

my $secret = pack 'A*', '12345678901234567890';
my $auth   = Auth::OATH::OTP->new;

subtest HMAC => sub {
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(0)), pack 'H*', 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(1)), pack 'H*', '75a48a19d4cbe100644e8ac1397eea747a2d33ab';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(2)), pack 'H*', '0bacb7fa082fef30782211938bc1c5e70416ff44';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(3)), pack 'H*', '66c28227d03a2d5529262ff016a1e6ef76557ece';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(4)), pack 'H*', 'a904c900a64b35909874b33e61c5938a8e15ed1c';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(5)), pack 'H*', 'a37e783d7b7233c083d4f62926c7a25f238d0316';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(6)), pack 'H*', 'bc9cd28561042c83f219324d3c607256c03272ae';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(7)), pack 'H*', 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(8)), pack 'H*', '1b3c89f65e6c9e883012052823443f048b4332db';
    is $auth->hmac($secret, Auth::OATH::OTP::pack_uint64(9)), pack 'H*', '1637409809a679dc698207310c8c7fc07290d9e5';
};

subtest '6-digit HOTP' => sub {
    is $auth->hotp($secret, 0), '755224';
    is $auth->hotp($secret, 1), '287082';
    is $auth->hotp($secret, 2), '359152';
    is $auth->hotp($secret, 3), '969429';
    is $auth->hotp($secret, 4), '338314';
    is $auth->hotp($secret, 5), '254676';
    is $auth->hotp($secret, 6), '287922';
    is $auth->hotp($secret, 7), '162583';
    is $auth->hotp($secret, 8), '399871';
    is $auth->hotp($secret, 9), '520489';
};

subtest '10-digit HOTP' => sub {
    local $auth->{digits} = 10;
    is $auth->hotp($secret, 0), '1284755224';
    is $auth->hotp($secret, 1), '1094287082';
    is $auth->hotp($secret, 2), '0137359152';
    is $auth->hotp($secret, 3), '1726969429';
    is $auth->hotp($secret, 4), '1640338314';
    is $auth->hotp($secret, 5), '0868254676';
    is $auth->hotp($secret, 6), '1918287922';
    is $auth->hotp($secret, 7), '0082162583';
    is $auth->hotp($secret, 8), '0673399871';
    is $auth->hotp($secret, 9), '0645520489';
};

done_testing;
