from engine.analysis_profiles import list_profiles, resolve_profile


def test_profiles_list_has_expected_ids():
    ids = [row["id"] for row in list_profiles()]
    assert ids == ["simple", "quick", "balanced", "deep", "forensic"]


def test_profile_resolution_escalates_deep_and_manual_flags():
    deep_profile = resolve_profile("quick", deep_analysis=True, manual_tools=False)
    assert deep_profile.profile_id == "deep"

    forensic_profile = resolve_profile("balanced", deep_analysis=False, manual_tools=True)
    assert forensic_profile.profile_id == "forensic"
