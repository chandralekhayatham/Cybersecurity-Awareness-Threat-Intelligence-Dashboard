def enrich_indicator(row,related_alerts=0,related_indicators=None,notes='Synthetic/demo enrichment; no external connection performed.'):
    return {**row,'related_alerts':related_alerts,'related_indicators':related_indicators or [],'analyst_notes':notes}
