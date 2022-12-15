# CodeQL



```bash
wget https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
tar xvf codeql-bundle-linux64.tar.gz

export PATH=/home/u1f383/codeql:$PATH

# 建立 linux kernel database
codeql database create kern_db --language=cpp --command="make -C /home/u1f383/kernel/linux-5.19.8 -j12"

# 跑單一
codeql query run -d=kern_db my.ql
codeql database analyze kern_db ./my.ql --format=sarifv2.1.0 --output=cpp-results.sarif --rerun

# 分析預設 qls
# 路徑： /home/u1f383/codeql/qlpacks/codeql/cpp-queries/0.4.2/Likely Bugs/AmbiguouslySignedBitField.ql
codeql database analyze kern_db --format=sarifv2.1.0 --output=cpp-results.sarif
```

- 雷：`@kind problem` 的格式為 element, string，需要保證是 string
  - 不過用 `query run` 就不用



### my.ql

```
/**
 * @name My
 * @description my ql
 * @kind problem
 * @problem.severity warning
 * @precision very-high
 * @id cpp/my
 * @tags maintainability
 *       readability
 *       language-features
 */

import cpp

from FunctionCall fc
        where fc.getTarget().getName() = "kmalloc"
select fc, fc.getLocation(), fc.getArgument(0).getValueText(), fc.getArgument(1).getValueText()
```



### qlpack.yml

```
library: false
name: codeql/cpp-queries
version: 0.4.2
buildMetadata:
  sha: a520de3986987baf4c5f846bd82bf68536ae042c
  cliVersion: 2.11.2
dependencies:
  codeql/cpp-all: '*'
  codeql/suite-helpers: '*'
suites: codeql-suites
extractor: cpp
groups:
 - cpp
 - queries
```



語法： https://codeql.github.com/codeql-standard-libraries/cpp/index.html