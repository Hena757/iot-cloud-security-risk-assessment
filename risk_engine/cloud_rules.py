"""Cloud-specific rule helpers (simple examples)."""

def default_cloud_properties():
	return {
		"public_exposure": False,
		"iam_principle_least_privilege": False,
		"logging_enabled": True,
	}


def map_asset_to_scope(asset_props: dict) -> str:
	return "cloud"
