import gensrrules


def test_combine():
    d1 = ["1.com", "google.com", "xxx.cloud.net", "xx.cloud.net"]
    d2 = ["1.com", "1.com", "cloud.net", "aaa.ccc"]
    assert gensrrules.combine_domain_suffices(d1, d2) == {
        "1.com",
        "cloud.net",
        "aaa.ccc",
    }
