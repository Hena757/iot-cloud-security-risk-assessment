"""IoT-specific rule helpers (simple examples)."""

def default_iot_asset_properties():
	return {
		"connectivity": "wifi",
		"auth": "basic",
		"firmware_up_to_date": False,
	}


def map_asset_to_scope(asset_props: dict) -> str:
	"""Return a scope label used to filter threats (iot/cloud/both).
	This is a tiny example — real rules would be richer.
	"""
	return "iot"
