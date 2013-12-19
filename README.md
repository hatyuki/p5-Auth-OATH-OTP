# NAME

Auth::OATH::OTP - OATH One Time Password

# SYNOPSIS

    use Auth::OATH::OTP;
    my $oath = Auth::OATH::OTP->new;
    my $totp = $oath->totp('MySecretPassword');
    my $hotp = $oath->hotp('MyOtherSecretPassword', 1);

# DESCRIPTION

Auth::OATH::OTP is implementation of the HOTP (RFC 4226) and TOTP (RFC 6238)
algorithms as defined by OATH. (http://www.openauthentication.org)

# METHODS

## __Auth::OATH::OTP->new(%options)__

    my $oath = Auth::OATH::OTP->new(
        algorithm => 'sha1',
        digits    =>  6,
        timestep  => 30,
    );

- __algorithm__

    Allowed values for _algorithm_ are 1, 224, 256, 384, 512, 512224, or 512256.
    For more information about this parameter, see also [Digest::SHA](http://search.cpan.org/perldoc?Digest::SHA).

    If the argument is missing, SHA-1 will be used by default.

- __digits__

    `totp()` and `hotp()` both default to returning 6 digits.

- __timestep__

    _timestep_ only applies to the `totp()` function.

    By default, the _timestep_ is 30 seconds, so there is a new password every 30 seconds.

## __$oath->totp($secret\_key\[, $time\]) : Integer__

    my $secret = pack 'A*', 'My Secret Key';
    my $totp   = $oath->totp($secret);
    # or
    my $totp   = $oath->totp($secret, time);

Manual _time_ is an optional parameter.
If it is missing, the current time will be used by default.
This is useful for testing purposes.

## __$oath->hotp($secret\_key, $counter) : Integer__

    my $secret = pack 'A*', 'My Secret Key';
    my $totp   = $oath->hotp($secret, 1);

Both parameters are required.

# LICENSE

Copyright (C) hatyuki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

hatyuki <hatyuki29@gmail.com>

# SEE ALSO

HOTP: [http://www.ietf.org/rfc/rfc4226.txt](http://www.ietf.org/rfc/rfc4226.txt)

TOTP: [http://www.ietf.org/rfc/rfc6238.txt](http://www.ietf.org/rfc/rfc6238.txt)

[Authen::OATH](http://search.cpan.org/perldoc?Authen::OATH)
