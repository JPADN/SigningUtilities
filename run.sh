cd out/artifacts/SigningUtilities_jar
zip -d SigningUtilities.jar META-INF/*.RSA META-INF/*.DSA META-INF/*.SF

cd ../../..

docker build . -t signing-utilities
docker run -v ${PWD}/etapas_1_2_output:/output signing-utilities