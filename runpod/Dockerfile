# Optional all-in-one image: the Incalmo attacker image plus the analysis deps,
# so the full generate -> extract -> analyze pipeline runs inside one pod.
#
# The range itself (attacker C2 + Equifax webserver/db) still comes up via
# docker/docker-compose.yml - this image only adds pandas/numpy/matplotlib/scipy
# (+ optional statsmodels) on top of the attacker image so research.analyze works
# in-pod instead of copying the CSV out. See runpod/README.md.
FROM incalmo-attacker:latest

# Analysis-only dependencies (the defender + sweep are pure stdlib).
COPY research/requirements-analysis.txt /tmp/requirements-analysis.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/requirements-analysis.txt || \
    uv pip install --system -r /tmp/requirements-analysis.txt

WORKDIR /incalmo
ENV PYTHONPATH=/incalmo
