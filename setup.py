import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="twilio-anchore",
    version="1.0.0",
    description="Twilio python library that facilitates the use of some features of the Anchore API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://code.hq.twilio.com/security/twilio-anchore-python-library",
    author="Juan Jose Lopez",
    author_email="jualopez@twilio.com",
    license='MIT',
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
        "Operating System :: OS Independent"
    ],
    keywords="anchore, containers, security",
    project_urls={
        "Source": "https://code.hq.twilio.com/security/twilio-anchore-python-library",
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    install_requires=[
        "requests==2.26.0",
        "pydantic==1.8.2"
    ],
    extras_require={  # Optional
        "dev": ["python-dotenv==0.19.2"]
    },
    python_requires=">=3.5"
)
