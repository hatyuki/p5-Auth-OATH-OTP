use strict;
use warnings;
use utf8;
use Auth::OATH::OTP::Verifier;
use File::Basename qw/ dirname /;
use JSON qw/ decode_json /;
use Plack::Builder;
use Plack::Request;
use Plack::Response;
use Plack::Session;
use Router::Boom;
use Text::MicroTemplate::DataSection qw/ render_mt /;
use URI::Escape qw/ uri_escape_utf8 /;

my $router = Router::Boom->new;
$router->add('/', sub {
        my ($request, $session) = @_;
        my $response = Plack::Response->new(200);
        my $auth     = Auth::OATH::OTP::Verifier->new(
            label  => 'demo@example.com',
            issuer => 'One-Time Passcode Demo',
        );
        my $body = render_mt('index.html', +{ key_uri => $auth->key_uri });

        $response->body($body);
        $session->set(secret => $auth->secret);

        return $response;
    },
);
$router->add('/verify', sub {
        my ($request, $session) = @_;
        my $response = Plack::Response->new;
        my $params   = decode_json($request->content);
        my $secret   = $session->get('secret');
        my $auth     = Auth::OATH::OTP::Verifier->new(secret => $secret);

        if ($secret && $auth->verify($params->{passcode})) {
            $response->status(200);
            $response->body('+ OK');
        } else {
            $response->status(403);
            $response->body('- NG');
        }

        return $response;
    },
);

my $app = sub {
    my $env      = shift;
    my $request  = Plack::Request->new($env);
    my $session  = Plack::Session->new($env);
    my $response = do {
        if (my ($action) = $router->match($env->{PATH_INFO})) {
            $action->($request, $session);
        } else {
            Plack::Response->new(404, [ ], 'Not Found');
        }
    };

    return $response->finalize;
};

builder {
    enable 'Static', path => qr{^/assets/}, root => dirname(__FILE__);
    enable 'Session';
    $app;
}

__DATA__

@@ index.html
<html lang="ja">
  <head>
    <title>Auth::OATH::OTP Demo</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.3/css/bootstrap.min.css" rel="stylesheet">
    <link href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.min.css" rel="stylesheet">
  </head>
  <body>
    <header>
      <nav class="navbar navbar-default navbar-static-top">
        <div class="navbar-header">
          <span class="navbar-brand">Auth::OATH::OTP Demo</span>
        </div>
      </nav>
    </header>

    <div class="container">
      <section>
        <h2>1. Download and install "Google Authenticator"</h2>
        <div class="container">
          <a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2">
            <img alt="Android app on Google Play" src="https://developer.android.com/images/brand/en_app_rgb_wo_45.png" />
          </a>
          <a href="https://itunes.apple.com/jp/app/google-authenticator/id388497605">
            <img alt="Download on the App Store" width="135" height="40" src="assets/appstore.png" />
          </a>
        </div>
      </section>

      <section>
        <h2>2. Scanning the QR code</h2>
        <div class="container">
          <img src="https://chart.googleapis.com/chart?chs=150x150&cht=qr&chld=L|0&chl=<?= uri_escape_utf8($_[0]->{key_uri}) ?>" alt="QR Code" />
        </div>
      </section>

      <section ng-app="demoApp">
        <h2>3. Input your One-Time Passcode and verify it</h2>
        <div class="container" ng-controller="VerifyCtrl">
          <form ng-submit="verify(passcode)">
            <div class="form-group">
              <label>One-Time Passcode</label>
              <input class="form-control input-sm" type="text" pattern="\d{6}" required ng-model="passcode" />
            </div>
            <button class="btn btn-primary" type="submit">Verifying One-Time Passcode</button>
          </form>
          <h1 class="{{ status.color }}"><span class="glyphicon {{ status.icon }}"></span> {{ status.message }}</h1>
        </div>
      </section>

    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.2.7/angular.min.js"></script>
    <script src="assets/controllers.js"></script>
  </body>
</html>
