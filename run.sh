cd out/artifacts/signingutilities_jar
zip -d signingutilities.jar META-INF/*.RSA META-INF/*.DSA META-INF/*.SF

cd ../../..

docker build . -t signing-utilities
docker run -v ${PWD}/etapas_1_2_output:/output signing-utilities