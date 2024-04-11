import subprocess

def install_dependencies():
    # 依赖项列表
    dependencies = [
        'cryptography',
        'ecdsa',
        'hashlib'
    ]

    # 循环安装每个依赖项
    for dependency in dependencies:
        # 使用 pip 安装依赖项
        subprocess.run(['pip', 'install', dependency])


if __name__ == '__main__':
    install_dependencies()
