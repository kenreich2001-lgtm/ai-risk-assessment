"""
Streamlit UI for risk–control mapping (`map_use_case`).

Run from this directory: streamlit run app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# project/ is the package root for `mapping_engine`
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mapping_engine import map_use_case

st.set_page_config(page_title="AI risk–control mapping", layout="wide")
st.title("AI risk–control mapping")

use_case = st.text_area("Use case description", height=180, placeholder="Describe the GenAI/system context…")
extra_raw = st.text_input("Optional extra tags (comma-separated)", "")

if st.button("Map use case", type="primary"):
    extras = [x.strip() for x in extra_raw.split(",") if x.strip()]
    result = map_use_case(use_case, extras if extras else None)

    st.subheader("Executive Summary")
    st.info(result.get("executive_summary", ""))

    st.subheader("Inferred tags")
    st.write(", ".join(result.get("tags", [])) or "(none)")

    st.subheader("Mapping table")
    table = result.get("mapping_table", [])
    if table:
        st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)
    else:
        st.caption("No mapping rows.")
