package Auth::OATH::OTP;
our $VERSION = '0.0001';
use 5.008001;
use strict;
use warnings;
use Carp ( );
use Digest::SHA ( );
use Math::Int64 ( );
use Class::Accessor::Lite (
    new => 0,
    ro  => [qw/ algorithm digits timestep /],
);

sub new
{
    my $class = shift;
    my %args  = scalar @_ == 1 && ref $_[0] eq 'HASH' ? %{ $_[0] } : @_;

    if (defined $args{digits} && $args{digits} < 6) {
        Carp::croak "'digits' must be at least 6 characters";
    }

    return bless +{
        algorithm => $args{algorithm} || 'sha1',
        digits    => $args{digits}    ||  6,
        timestep  => $args{timestep}  || 30,
    }, $class;
}

sub totp
{
    my ($self, $secret, $time) = @_;
    my $bincode = pack_uint64($self->timestamp($time));
    return $self->compute_code($secret, $bincode);
}

sub hotp
{
    my ($self, $secret, $counter) = @_;
    my $bincode = pack_uint64($counter);
    return $self->compute_code($secret, $bincode);
}

sub timestamp
{
    my ($self, $time) = @_;
    $time = time unless defined $time;
    return int $time / $self->timestep;
}

sub pack_uint64
{
    return Math::Int64::uint64_to_net("$_[0]");
}

sub compute_code
{
    my ($self, $secret, $bincode) = @_;
    my @hash   = unpack 'C*', $self->hmac($secret, $bincode);
    my $offset = $hash[-1] & 0xF;
    my $digits = $self->digits;

    return sprintf "%0${digits}u", (
        ($hash[$offset + 0] & 0x7F) << 24 |
        ($hash[$offset + 1] & 0xFF) << 16 |
        ($hash[$offset + 2] & 0xFF) <<  8 |
        ($hash[$offset + 3] & 0xFF)
    ) % 10 ** $digits;
}

sub hmac
{
    my ($self, $secret, $bincode) = @_;
    my $algorithm = $self->algorithm;
    $algorithm =~ s/\D+//;

    if (my $digest = Digest::SHA->can("hmac_sha${algorithm}")) {
        return $digest->($bincode, $secret);
    }

    Carp::croak "Unknown algorithm 'HMAC-SHA${algorithm}'";
}

1;

__END__

=encoding utf-8

=head1 NAME

Auth::OATH::OTP - OATH One-Time Passcode Generator

=head1 SYNOPSIS

    use Auth::OATH::OTP;
    my $oath = Auth::OATH::OTP->new;
    my $totp = $oath->totp('MySecretPassword');
    my $hotp = $oath->hotp('MyOtherSecretPassword', 1);

=head1 DESCRIPTION

Auth::OATH::OTP is implementation of the HOTP (RFC 4226) and TOTP (RFC 6238)
algorithms as defined by OATH. (http://www.openauthentication.org)

=head1 METHODS

=head2 B<< Auth::OATH::OTP->new(%options) >>

    my $oath = Auth::OATH::OTP->new(
        algorithm => 'sha1',
        digits    =>  6,
        timestep  => 30,
    );

=over

=item B<algorithm>

Allowed values for I<algorithm> are 1, 224, 256, 384, 512, 512224, or 512256.
For more information about this parameter, see also L<Digest::SHA>.

If the argument is missing, SHA-1 will be used by default.

=item B<digits>

C<totp()> and C<hotp()> both default to returning 6 digits.

=item B<timestep>

I<timestep> only applies to the C<totp()> function.

By default, the I<timestep> is 30 seconds, so there is a new password every 30 seconds.

=back

=head2 B<< $oath->totp($secret_key[, $time]) : Integer >>

    my $secret = pack 'A*', 'My Secret Key';
    my $totp   = $oath->totp($secret);
    # or
    my $totp   = $oath->totp($secret, time);

Manual I<time> is an optional parameter.
If it is missing, the current time will be used by default.
This is useful for testing purposes.

=head2 B<< $oath->hotp($secret_key, $counter) : Integer >>

    my $secret = pack 'A*', 'My Secret Key';
    my $totp   = $oath->hotp($secret, 1);

Both parameters are required.

=head1 LICENSE

Copyright (C) hatyuki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

hatyuki E<lt>hatyuki29@gmail.comE<gt>

=head1 SEE ALSO

HOTP: L<http://www.ietf.org/rfc/rfc4226.txt>

TOTP: L<http://www.ietf.org/rfc/rfc6238.txt>

L<Authen::OATH>

=cut
