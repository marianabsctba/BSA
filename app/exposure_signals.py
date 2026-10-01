from dataclasses import dataclass

@dataclass(frozen=True)
class ExposureSignal:
    kind: str
    value: str
    confidence: int
    reason: str
    validation_required: bool=False

CLOUD_PATTERNS={
    "aws":("amazonaws.com","cloudfront.net","elb.amazonaws.com"),
    "azure":("azurewebsites.net","cloudapp.azure.com","trafficmanager.net","blob.core.windows.net"),
    "gcp":("googleusercontent.com","appspot.com","cloudfunctions.net"),
    "cloudflare":("cloudflare.com","cloudflare.net"),
    "vercel":("vercel.app","vercel-dns.com"),
    "netlify":("netlify.app","netlify.com"),
    "github_pages":("github.io","githubusercontent.com"),
}

TAKEOVER_PATTERNS={
    "aws_s3":("NoSuchBucket","The specified bucket does not exist"),
    "github_pages":("There isn't a GitHub Pages site here","For root URLs"),
    "heroku":("No such app","herokudns"),
    "azure":("404 Web Site not found","azurewebsites.net"),
    "netlify":("Not Found - Request ID","netlify.app"),
}

def cloud_signals(values):
    out=[]
    seen=set()
    seen=set()
    for value in values:
        v=str(value).lower()
        for provider,patterns in CLOUD_PATTERNS.items():
            if any(p in v for p in patterns):
                key=(provider, str(value).lower())
                if key not in seen:
                    seen.add(key)
                    key=(provider, str(value).lower())
                if key not in seen:
                    seen.add(key)
                    out.append(ExposureSignal("cloud_provider",provider,88,f"hostname/DNS value matches {provider} infrastructure"))
    return out

def takeover_signals(http_values):
    out=[]
    seen=set()
    seen=set()
    for value in http_values:
        text=str(value)
        low=text.lower()
        for provider,patterns in TAKEOVER_PATTERNS.items():
            if any(p.lower() in low for p in patterns):
                key=(provider, text[:180])
                if key not in seen:
                    seen.add(key)
                    out.append(ExposureSignal("potential_takeover",provider,72,"response matches known provider orphaning pattern; ownership validation required",True))
    return out

def summarize_signals(signals):
    return {"signals":[s.__dict__ for s in signals],
            "cloud_providers":sorted({s.value for s in signals if s.kind=="cloud_provider"}),
            "potential_takeovers":[s.value for s in signals if s.kind=="potential_takeover"],
            "validation_required":sum(1 for s in signals if s.validation_required)}
