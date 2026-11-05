package site.aicc.fuzz;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** A short run of the harness on every test run; {@link PublicApiFuzz#main} is the long one. */
public class PublicApiFuzzTest {
  @Test
  public void publicSurfaceKeepsTheFailureConvention() throws Exception {
    PublicApiFuzz.Report report = PublicApiFuzz.run(500, 2, 7);
    assertTrue(report.casesPerMethod.size() > 100);
    assertEquals(String.valueOf(report.findings), 0, report.findings.size());
  }
}
