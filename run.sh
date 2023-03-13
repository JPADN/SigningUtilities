docker build . -t signing-utilities
docker run -v ${PWD}/etapas_1_2_output:/app/etapas_1_2_output signing-utilities