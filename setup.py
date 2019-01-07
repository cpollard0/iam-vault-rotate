from setuptools import setup

setup(
    name='iam_vault_rotate',
    version='.001',
    description='A utility for rotating ansible-vaulted IAM service accounts',
    scripts=['iam_vault_rotate.py'],
    py_modules=['iam_vault_rotate'],
    install_requires=[
        'boto3',
        'ansible_vault',
        'ruamel.yaml',
		'ansible'
    ],
    entry_points={
        'console_scripts': [
            'iam_vault_rotate = iam_vault_rotate:main'
        ]
    }
)