package Auth::OATH::OTP::Verifier;
use strict;
use warnings;
use parent qw/ Auth::OATH::OTP /;
use Carp ( );
use Convert::Base32 ( );
use List::Util ( );
use URI::Escape ( );
use Class::Accessor::Lite (
    new => 0,
    ro  => [qw/ algorithm binkey digits label secret timestep types window /],
);

sub new
{
    my $class = shift;
    my %args  = scalar @_ == 1 && ref $_[0] eq 'HASH' ? %{ $_[0] } : @_;

    unless (defined $args{secret}) {
        $args{secret} = generate_secret_key(32);
    }

    return bless +{
        algorithm => 'sha1',
        binkey    => Convert::Base32::decode_base32($args{secret}),
        digits    => 6,
        label     => '',
        timestep  => 30,
        types     => 'totp',
        window    => 3,
        %args,
    }, $class;
}

sub generate_secret_key
{
    my $length = defined $_[0] && $_[0] > 0 ? $_[0] : 32;
    my @chars  = List::Util::shuffle('A'..'Z', 2..7);
    return join '', map { $chars[int rand 32] } 1..$length;
}

sub verify
{
    my ($self, $code, $seed) = @_;
    return 0 unless defined $code;

    my $method = lc $self->types;
    Carp::croak "Unknown algorithm '$method'" unless $self->can($method);

    my $window = $method eq 'totp' ? $self->window : 1;
    for (my $i = int -(($window - 1) / 2) ; $i < $window / 2 ; ++$i) {
        return 1 if $self->$method($seed) == $code;
    }

    return 0;
}

sub totp
{
    my ($self, $time) = @_;
    return $self->SUPER::totp($self->binkey, $time);
}

sub hotp
{
    my ($self, $counter) = @_;
    return $self->SUPER::hotp($self->binkey, $counter);
}

sub key_uri
{
    my $self   = shift;
    my $types  = lc $self->types;
    my $label  = URI::Escape::uri_escape($self->label);
    my $secret = '?secret=' . $self->secret;
    return sprintf 'otpauth://%s/%s?%s',$types, $label, $secret;
}

1;

__END__

=encoding utf-8

=head1 NAME

Auth::OATH::OTP::Verifier - One-Time Passcode Verifier

=head1 SYNOPSIS

    use Auth::OATH::OTP::Verifier;
    my $auth = Auth::OATH::OTP::Verifier->new;

    # Authentification
    if ($auth->verify('012345')) {
        # Success
    } else {
        # Fail
    }

    # Generate Time-based One Time Passcode
    my $totp_code = $auth->totp;

    # Generate HMAC-based One Time Passcode
    my $totp_code = $auth->hotp(15);

=head1 DESCRIPTION

Auth::OATH::OTP::Verifier is ...

=head1 METHODS

=head2 B<< Auth::OATH::OTP::Verifier->new(%options) >>

    my $oath = Auth::OATH::OTP->new(
        algorithm => 'sha1',
        digits    =>  6,
        timestep  => 30,
        label     => 'My Authentification',
        types     => 'TOTP', # Lower-case letters are also allowed.
        window    => 3,
        secret    => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    );

=over

=item B<algorithm>

=item B<digits>

=item B<timestep>

If you want to know about these parameters, see L<Auth::OATH::OTP>.

=item B<label>

The label is used to identify which account a key is associated with.

=item B<types>

Valid I<types> are B<HOTP> and B<TOTP>,to distinguish whether the key will be
used for counter-based HOTP or for TOTP.

=item B<window>

If the argument is missing, 3 will be used by default.

=item B<secret>

The I<secret> parameter is an arbitrary secret key value encoded in Base32 according to RFC 3548.
If the argument is missing, random Base32 string of length 32 will be used by default.

=back

=head2 B<< $oath->verify($code) : Boolean >>

    my $totp_verifier   = Auth::OATH::OTP::Verifier->new(types => 'totp');
    my $totp_is_success = $totp_verifier->verify($code[, $time]);
    # or
    my $hotp_verifier   = Auth::OATH::OTP::Verifier->new(types => 'hotp');
    my $hotp_is_success = $hotp_verifier->verify($code, $counter]);

=head2 B<< $oath->totp([$time]) : String >>

    my $totp = $oath->totp;
    # or
    my $totp = $oath->totp(time);

Returns a text string with the Time-based One Time Passcode.

Manual I<time> is an optional parameter.
If it is missing, the current time will be used by default.
This is useful for testing purposes.

=head2 B<< $oath->hotp($counter) : String >>

    my $hotp = $oath->hotp(12345);

Returns a text string with the HMAC-based One Time Passcode.

=head1 LICENSE

Copyright (C) hatyuki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

hatyuki E<lt>hatyuki29@gmail.comE<gt>

=head1 SEE ALSO

Google Authenticator: http://code.google.com/p/google-authenticator/

L<Auth::GoogleAuthenticator>

L<Auth::OATH::OTP>

=cut
