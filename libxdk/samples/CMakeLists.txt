# samples/CMakeLists.txt
project(kernelXDKSamples)

set(SAMPLE_NAMES
    exp151
)

# Add Individual Sample Subdirectories
# Each of these subdirectories must contain its own CMakeLists.txt (e.g., samples/exp151/CMakeLists.txt)
foreach(SAMPLE_DIR ${SAMPLE_NAMES})
    # TODO if if we want it to compile samples in the main build
    # add_subdirectory(${SAMPLE_DIR})
endforeach()

