# IPv6 Testing and generating Adoption Stats

The ideas here is very simple, test and examine data on who has the most popular websites running IPv6.

I was recently at the APNIC-60 conference in Vietnam, where I tried being on ipv6-only for some time.

Google and other regular use sites worked, but GITHUB did not, and several ipv6 test sites also failed.

- Ref: http://bit.ly/4ntFNAG (and trace: https://urlscan.io/result/01994552-c402-7277-b630-565adbf7cb7a/ )

- Top 1M Sites: http://s3.amazonaws.com/alexa-static/top-1m.csv.zip (no longer works!)

- Possible replacement: https://gist.githubusercontent.com/bejaneps/ba8d8eed85b0c289a05c750b3d825f61/raw/6827168570520ded27c102730e442f35fb4b6a6d/websites.csv (5 years old!)

# Notes

The methodology from script to script varied, but testing relies bare ip addresses with host headers mostly.

If the redirects exceed 30 on those requests to a live ipv6 address on vanila HTTP, it is still a fail.

