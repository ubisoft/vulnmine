# Running vulnmine tests

This article describes how to initialize and run the automated pytest framework used by Vulnmine.

## Running all the tests

First of all, start a bash shell **in the pyprod Docker container**.
(See _"Use.md"_ for more information on this. The tests have been built to run with Docker, not directly from the source code.)

Then simply run the "pytest" command. Use "-v" to see the details of the tests executed.

```bash
docker-compose run --rm pyprod bash

cd /home/jovyan/work/tests
pytest [-v]
```


## Running a specific test

The test code is in the **_tests/_** directory:

| File | Purpose |
| ---- | ------- |
| _conftest.py_ | Initialize test environment |
| _context.py_ | python imports |
| _test_0_sccm.py_| Test SccmHosts, SccmSoft classes |
| _test_1_nvd.py_ | Test NvdCpe, NvdCve classes including mock download |
| _test_2_matching.py_ | Test MatchVendor, MatchSoft classes |

To run a specific test:

```bash
pytest test_sccm.py::TestSccm::test_read_hosts
pytest test_sccm.py::TestSccm::test_sccm_sft
```

## Important notes

### Debugging failed tests by manual simulation

To manually simulate a failed test, start a bash shell as described above (cf "Running all the tests")

Then the test environment has to manually initialized.

* Start python
* Copy/paste the imports and the init_testenv rtn from tests/conftest.py

```python
python
import ...

# copy / paste init_testenv()

init_testenv()

# now start manual simulation of failed test
```

### Rebuilding test baseline pickled dataframes after pandas / python version upgrade

If there is a pandas / python version upgrade, then the test "baseline" dataframes (in pickled format) will likely no longer load. Extraneous errors can also occur.

The solution is to rebuild all these files by running the tests in reverse. The code to do this is in the following files: _tests/rebuild_test_baseline_*_pck.py_

Normally this code is configured to be ignored by pytest.

Edit each _rebuild_test_baseline_*_pck.py_ file:

* Find line containing **"@pytest.mark.skip":**
* Comment out this line.
* Save the file.

Then start the pyprod container as above and run the above-mentioned tests one at a time.

```bash
cd /home/jovyan/work/tests
pytest -v rebuild_test_baseline_sccm_nvd_pck.py
pytest -v rebuild_test_baseline_matching_pck.py
```

Note that these tests will "fail" because of a hardcoded "False" assertion included at end of each pgm. This forces pytest to dump out intermediate results that can be used to check that everything in fact executed correctly.

When all the test baseline files have been rebuilt properly, then edit the files again to remove the comments.
