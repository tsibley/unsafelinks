# Safelinks on Outlook 365 intercepts clicks on links and instead navigates to:
#
#     GET https://outlook.office.com/mail/safelink.html?corid=…&url=
#
# JavaScript on that page then makes a request behind the scenes to the
# Safelinks backend:
#
#     POST https://nam02.safelinks.protection.outlook.com/GetUrlReputation Url=…
#
# If the Safelinks backend is satisfied, it responds with a 302 to the given
# Url and the frontend JS notices that and navigates the browser viewport
# there.
#
# In addition to that, Proofpoint's URL defense product has already permanently
# rewritten URLs in the email to wrap them with their own checks, e.g.:
#
#     https://urldefense.com/v3/__https://github.com/nextstrain/augur/pull/1175*discussion_r1130183899__;Iw!!GuAItXPztq0!jULEM6V…DcY$
#
# for the original URL:
#
#     https://github.com/nextstrain/augur/pull/1175#discussion_r1130183899
#
# All of this is terrible and results in it taking ~3-4s to open a link in my
# work email.
#
# Well, I can do terrible things too, starting with intercepting the Safelinks
# backend request to cut out time-consuming "safety" checks and unwrapping the
# Proofpoint fuckery while I'm at it.  I still have to wait for the frontend JS
# to make the request and perform the browser navigation, but at least it's
# only ~1s or so (orz) now to open a link.
#
# It would be better to cut Safelinks entirely out of the click, but that
# involves either a) injecting user scripts into outlook.office.com and doing
# live, continual modification of the DOM (and dealing with event handlers we
# don't have references to) or b) proxying all of outlook.office.com.  I'm not
# keen on either but might still end up resorting to one of them if this
# terrible hack doesn't work well enough.
#   -trs, 10 March 2023
#
# P.S. There's actually some decent info on the different kinds of terrible
# things Safelinks can do documented at:
#
#     <https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-about>
#
# Some of these my work hasn't enabled (e.g. Safelinks can _also_ permanently
# rewrite URLs in emails).
#
use Plack::Builder;
use Plack::Request;
use List::Util qw< pairgrep pairs >;
use URI;

sub unfuck {
    # URL Defense mangled this:
    #
    #   https://www.google.com/url?q=https://github.com/nextstrain/ebola/blob/bb9421bacbb2a3ce5db48c22cd716041858c913f/ingest/workflow/snakemake_rules/transform.smk#23L76-L84
    #
    # into:
    #
    #   https://www.google.com/url?q=https:**Agithub.com*nextstrain*ebola*blob*bb9421bacbb2a3ce5db48c22cd716041858c913f*ingest*workflow*snakemake_rules*transform.smk*23L76-L84
    #
    # Ugh my head.  WTF is "**A"??  Do not understand that yet.
    my $url = shift;
       $url =~ s{(?<=http[s]:)[*][*]A}{//};     # Replace "https:**A" with "https://"
       $url =~ s{(.*)[*]}{$1#};                 # Replace last "*" with a "#" (terrible heuristic)
       $url =~ s{[*]}{/}g;                      # Replace remaining "*" with "/"
    return $url;
}

sub deurchin {
    my $url = URI->new(shift);

    # Remove Google Analytics (Urchin) tracking params.
    $url->query_form([ pairgrep { $a !~ /^utm_/ } $url->query_form ]);

    return $url;
}

builder {
    enable "SimpleLogger", level => "info";

    sub {
        my $req = Plack::Request->new(shift);

        return [404, [], []] unless $req->path eq "/GetUrlReputation";
        return [405, [], []] unless $req->method eq "POST";

        my $url = $req->parameters->{Url};
           $url =~ s{\Ahttps://urldefense[.]com/v3/__(.+?)__;.*\z}{unfuck($1)}se;
           $url = deurchin($url);

        $req->logger->({ level => "info", message => "Redirecting to <$url>" });

        return [302, ["Location", $url], []];
    }
}
