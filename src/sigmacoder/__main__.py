"""允许通过 ``python -m sigmacoder`` 调用公共 CLI。"""

from sigmacoder.cli import main

raise SystemExit(main())
