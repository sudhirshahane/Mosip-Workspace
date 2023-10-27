package io.mosip.kernel.core.test.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import io.mosip.kernel.core.exception.IllegalArgumentException;
import io.mosip.kernel.core.exception.ParseException;
import io.mosip.kernel.core.util.DateUtils;

/**
 * Unit test for simple App.
 */
@RunWith(MockitoJUnitRunner.class)
public final class DateUtilTest {

	private static Date TEST_DATE;

	private static Calendar TEST_CALANDER;

	private static String TEST_CALANDER_STRING;

	private static Date currDate;

	private static Calendar calendar;

	private static LocalDateTime currLocalDateTime;

	@BeforeClass
	public static void setup() {
		final GregorianCalendar cal = new GregorianCalendar(2018, 6, 5, 4, 3, 2);
		cal.set(Calendar.MILLISECOND, 1);
		TEST_DATE = cal.getTime();

		cal.setTimeZone(TimeZone.getDefault());

		TEST_CALANDER = cal;

		StringBuilder builder = new StringBuilder();
		builder.append(cal.get(Calendar.YEAR));
		builder.append(cal.get(Calendar.MONTH) + 1);
		builder.append(cal.get(Calendar.DAY_OF_MONTH));
		builder.append(cal.get(Calendar.HOUR_OF_DAY));
		TEST_CALANDER_STRING = builder.toString();
		currDate = new Date();
		currLocalDateTime = LocalDateTime.now();

	}

	@Test
	public void testAddDays() throws Exception {
		Date result = DateUtils.addDays(TEST_DATE, 0);

		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 3, 2, 1);

		result = DateUtils.addDays(TEST_DATE, 1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 6, 4, 3, 2, 1);

		result = DateUtils.addDays(TEST_DATE, -1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 4, 4, 3, 2, 1);

	}

	@Test
	public void testAddHours() throws Exception {
		Date result = DateUtils.addHours(TEST_DATE, 0);

		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 3, 2, 1);

		result = DateUtils.addHours(TEST_DATE, 1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 5, 3, 2, 1);

		result = DateUtils.addHours(TEST_DATE, -1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 3, 3, 2, 1);

	}

	@Test
	public void testAddMinutes() throws Exception {
		Date result = DateUtils.addMinutes(TEST_DATE, 0);

		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 3, 2, 1);

		result = DateUtils.addMinutes(TEST_DATE, 1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);

		assertDate(result, 2018, 6, 5, 4, 4, 2, 1);

		result = DateUtils.addMinutes(TEST_DATE, -1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 2, 2, 1);

	}

	@Test
	public void testAddSeconds() throws Exception {
		Date result = DateUtils.addSeconds(TEST_DATE, 0);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 3, 2, 1);

		result = DateUtils.addSeconds(TEST_DATE, 1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 3, 3, 1);

		result = DateUtils.addSeconds(TEST_DATE, -1);
		assertNotSame(TEST_DATE, result);
		assertDate(TEST_DATE, 2018, 6, 5, 4, 3, 2, 1);
		assertDate(result, 2018, 6, 5, 4, 3, 1, 1);
	}

	@Test
	public void testFormatCalender() throws Exception {
		assertEquals(TEST_CALANDER_STRING, DateUtils.formatCalendar(TEST_CALANDER, "yyyyMdH"));
		assertEquals(TEST_CALANDER_STRING, DateUtils.formatCalendar(TEST_CALANDER, "yyyyMdH", Locale.US));
		assertEquals(TEST_CALANDER_STRING, DateUtils.formatCalendar(TEST_CALANDER, "yyyyMdH", TimeZone.getDefault()));
		assertEquals(TEST_CALANDER_STRING,
				DateUtils.formatCalendar(TEST_CALANDER, "yyyyMdH", TimeZone.getDefault(), Locale.US));
	}

	@Test
	public void testFormatDate() throws Exception {
		assertEquals(TEST_CALANDER_STRING, DateUtils.formatDate(TEST_CALANDER.getTime(), "yyyyMdH"));
		assertEquals(TEST_CALANDER_STRING,
				DateUtils.formatDate(TEST_CALANDER.getTime(), "yyyyMdH", TimeZone.getDefault()));
		assertEquals(TEST_CALANDER_STRING,
				DateUtils.formatDate(TEST_CALANDER.getTime(), "yyyyMdH", TimeZone.getDefault(), Locale.US));
	}

	private void assertDate(final Date date, final int year, final int month, final int day, final int hour,
			final int min, final int sec, final int mil) throws Exception {
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setTime(date);
		assertEquals(year, cal.get(Calendar.YEAR));
		assertEquals(month, cal.get(Calendar.MONTH));
		assertEquals(day, cal.get(Calendar.DAY_OF_MONTH));
		assertEquals(hour, cal.get(Calendar.HOUR_OF_DAY));
		assertEquals(min, cal.get(Calendar.MINUTE));
		assertEquals(sec, cal.get(Calendar.SECOND));
		assertEquals(mil, cal.get(Calendar.MILLISECOND));
	}

	// --------------------------------- Test for after---------------
	private void loadDate() {
		calendar = Calendar.getInstance();
		calendar.setTime(currDate);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDateAfter() {

		loadDate();
		calendar.add(Calendar.DATE, 1);

		Date nextDate = calendar.getTime();

		assertTrue(DateUtils.after(nextDate, currDate));

		assertFalse(DateUtils.after(currDate, nextDate));

		assertFalse(DateUtils.after(currDate, currDate));
		DateUtils.after(null, new Date());

	}

	@Test(expected = IllegalArgumentException.class)
	public void testDateAfterException() {
		DateUtils.after(null, LocalDateTime.now());
	}

	@Test
	public void testLocalDateTimeAfter() {

		LocalDateTime nextLocalDateTime = currLocalDateTime.plusDays(1);

		assertTrue(DateUtils.after(nextLocalDateTime, currLocalDateTime));

		assertFalse(DateUtils.after(currLocalDateTime, nextLocalDateTime));

		assertFalse(DateUtils.after(currLocalDateTime, currLocalDateTime));
	}

	// --------------------------------- Test for before-------------------
	@Test(expected = IllegalArgumentException.class)
	public void testDateBefore() {

		loadDate();
		calendar.add(Calendar.DATE, -1);
		Date previousDay = calendar.getTime();

		assertTrue(DateUtils.before(previousDay, currDate));

		assertFalse(DateUtils.before(currDate, previousDay));

		assertFalse(DateUtils.before(currDate, currDate));

		DateUtils.before(null, currDate);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDateBeforeException() {
		DateUtils.before(null, LocalDateTime.now());
	}

	@Test
	public void testLocalDateTimeBefore() {

		LocalDateTime previousLocalDateTime = currLocalDateTime.minusDays(1);

		assertTrue(DateUtils.before(previousLocalDateTime, currLocalDateTime));

		assertFalse(DateUtils.before(currLocalDateTime, previousLocalDateTime));

		assertFalse(DateUtils.before(currLocalDateTime, currLocalDateTime));
	}

	// --------------------------------- Test for equal----------------------
	@Test(expected = IllegalArgumentException.class)
	public void testIsSameDayWithNextLocalDateTime() {
		LocalDateTime nextLocalDateTime = currLocalDateTime.plusDays(1);

		assertTrue(DateUtils.isSameDay(currLocalDateTime, currLocalDateTime));

		assertFalse(DateUtils.isSameDay(currLocalDateTime, nextLocalDateTime));

		assertFalse(DateUtils.isSameDay(nextLocalDateTime, currLocalDateTime));

		DateUtils.isSameDay(null, currLocalDateTime);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIsSameDayException() {
		DateUtils.isSameDay(null, new Date());
	}

	@Test
	public void testIsSameDayWithNextDate() {
		loadDate();
		calendar.add(Calendar.DATE, 1);
		Date nextDate = calendar.getTime();

		assertTrue(DateUtils.isSameDay(currDate, currDate));

		assertFalse(DateUtils.isSameDay(currDate, nextDate));

		assertFalse(DateUtils.isSameDay(nextDate, currDate));
	}

	@Test
	public void testIsSameDayWithDifferentTime() {
		loadDate();
		calendar.add(Calendar.MILLISECOND, 1);
		Date nextDate = calendar.getTime();

		assertTrue(DateUtils.isSameDay(currDate, currDate));

		assertTrue(DateUtils.isSameDay(currDate, nextDate));

		assertTrue(DateUtils.isSameDay(nextDate, currDate));
	}

	// @Test
	public void testIsSameDayWithDifferentLocalDateTime() {

		LocalDateTime nextLocalDateTime = currLocalDateTime.plusHours(1);

		assertTrue(DateUtils.isSameDay(currLocalDateTime, currLocalDateTime));

		assertTrue(DateUtils.isSameDay(currLocalDateTime, nextLocalDateTime));

		assertTrue(DateUtils.isSameDay(nextLocalDateTime, currLocalDateTime));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIsSameInstantWithDifferentLocalDateTime() {

		LocalDateTime nextLocalDateTime = currLocalDateTime.plusHours(1);

		assertTrue(DateUtils.isSameInstant(currLocalDateTime, currLocalDateTime));

		assertFalse(DateUtils.isSameInstant(currLocalDateTime, nextLocalDateTime));

		assertFalse(DateUtils.isSameInstant(nextLocalDateTime, currLocalDateTime));
		DateUtils.isSameInstant(null, currLocalDateTime);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIsSameInstantWithDifferentDate() {
		DateUtils.isSameInstant(null, new Date());
	}

	@Test
	public void testIsSameInstantWithDifferentTime() {
		loadDate();
		calendar.add(Calendar.SECOND, 1);
		calendar.add(Calendar.MILLISECOND, 1);
		Date nextDate = calendar.getTime();

		assertTrue(DateUtils.isSameInstant(currDate, currDate));

		assertFalse(DateUtils.isSameInstant(currDate, nextDate));

		assertFalse(DateUtils.isSameInstant(nextDate, currDate));
	}

	// --------------------------------- Test for exception----------------------
	@Test(expected = IllegalArgumentException.class)
	public void testDateAfterExceptionDateNull() {
		DateUtils.after(null, currDate);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDateBeforeExceptionDateNull() {
		DateUtils.before(currDate, null);
	}

	// -----------------------------Parsing date test----------------------------

	@Test
	public void testGetUTCCurrentDateTime() {
		assertNotNull(DateUtils.getUTCCurrentDateTime());
	}

	@Test
	public void testParseUTCToDefaultLocalDateTime() {
		assertNotNull(DateUtils.convertUTCToLocalDateTime(DateUtils.getCurrentDateTimeString()));
	}

	@Test
	public void testParseUTCToLocalDateTime() {
		LocalDateTime exp = LocalDateTime.parse("2018/11/20 20:02:39",
				DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
		ZonedDateTime z1 = exp.atZone(ZoneId.of(TimeZone.getDefault().getID()));
		LocalDateTime utcDateTime = LocalDateTime.ofInstant(z1.toInstant(), ZoneOffset.UTC);
		LocalDateTime act = DateUtils.parseUTCToLocalDateTime(utcDateTime.toString(), "yyyy-MM-dd'T'HH:mm:ss");
		compareTwoLocalDateTime(exp, act);
	}

	@Test
	public void testParseToDate() throws java.text.ParseException {
		assertNotNull(DateUtils.parseToDate("2018/11/20 20:02:39", "yyyy/MM/dd HH:mm:ss", TimeZone.getDefault()));
	}

	private void compareTwoLocalDateTime(LocalDateTime exp, LocalDateTime act) {
		assertTrue(exp.getDayOfMonth() == act.getDayOfMonth());
		assertTrue(exp.getMonth() == act.getMonth());
		assertTrue(exp.getYear() == act.getYear());
		assertTrue(exp.getHour() == act.getHour());
		assertTrue(exp.getMinute() == act.getMinute());
		assertTrue(exp.getSecond() == act.getSecond());
	}

	public LocalDateTime convertToLocalDateTimeViaInstant(Date dateToConvert) {
		return dateToConvert.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
	}

	@Test(expected = io.mosip.kernel.core.exception.NullPointerException.class)
	public void testParseToDateExceptionNullDateString() throws java.text.ParseException {
		DateUtils.parseToDate(null, "dd-MM-yyyy");
	}

	@Test(expected = io.mosip.kernel.core.exception.NullPointerException.class)
	public void testParseToDateExceptionNullPatternString() throws java.text.ParseException {
		DateUtils.parseToDate("2019-01-01", null);
	}

	@Test(expected = io.mosip.kernel.core.exception.ParseException.class)
	public void testParseToDateParseException() throws java.text.ParseException {
		DateUtils.parseToDate("2019-01-01", "dd.MM.yyyy");
	}

	@Test
	public void testParseUtcToDate() throws java.text.ParseException {
		assertNotNull(DateUtils.parseToDate("2018/11/20 20:02:39", "yyyy/MM/dd HH:mm:ss", TimeZone.getTimeZone("UTC")));
	}

	@Test
	public void testGetUTCCurrentDateTimeString() {
		assertNotNull(DateUtils.getUTCCurrentDateTimeString());
	}

	@Test
	public void testFormatUTCCurrentDateTimeString() {
		assertNotNull(DateUtils.getUTCCurrentDateTimeString("yyyy/MM/dd HH:mm:ss"));
	}

	@Test(expected = DateTimeParseException.class)
	public void testParseUTCToDefaultLocalDateTimeException() {
		DateUtils.convertUTCToLocalDateTime("22-01-2108");
	}

	@Test(expected = ParseException.class)
	public void testParseUTCToLocalDateTimeException() {
		DateUtils.parseUTCToLocalDateTime("22-01-2108", "yyyy-MM-dd'T'HH:mm:ss.SSS");
	}

	// New test case added
	@Test(expected = IllegalArgumentException.class)
	public void addDaysIllegalArgumentException() {
		DateUtils.addDays(null, 2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void addHoursIllegalArgumentException() {
		DateUtils.addHours(null, 2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void addMinutesIllegalArgumentException() {
		DateUtils.addMinutes(null, 2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void addSecondsIllegalArgumentException() {
		DateUtils.addSeconds(null, 2);
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatDateIllegalArgumentException() {
		DateUtils.formatDate(new Date(), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatDateWithTimeZoneIllegalArgumentException() {
		DateUtils.formatDate(new Date(), null, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatDateWithTimeZoneLocaleIllegalArgumentException() {
		DateUtils.formatDate(new Date(), null, null, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatCalendarIllegalArgumentException() {
		DateUtils.formatCalendar(Calendar.getInstance(), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatCalendarZoneIllegalArgumentException() {
		DateUtils.formatCalendar(Calendar.getInstance(), null, TimeZone.getDefault());
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatCalendarLocaleIllegalArgumentException() {
		DateUtils.formatCalendar(Calendar.getInstance(), null, Locale.getDefault());
	}

	@Test(expected = IllegalArgumentException.class)
	public void formatCalendarZoneLocalIllegalArgumentException() {
		DateUtils.formatCalendar(Calendar.getInstance(), null, TimeZone.getDefault(), null);
	}

	@Test
	public void parseToLocalDateTime() {
		DateUtils.parseToLocalDateTime(LocalDateTime.now().toString());
	}

	@Test
	public void formatToISOString() {
		DateUtils.formatToISOString(LocalDateTime.now());
	}

	@Test(expected = ParseException.class)
	public void parseUTCToDate() {
		DateUtils.parseUTCToDate(LocalDateTime.now().toString(), "dd.MM.yyyy");
	}

	@Test(expected = ParseException.class)
	public void parseUTCToDateStirng() {
		DateUtils.parseUTCToDate("2019.01.01");
	}

	@Test(expected = ParseException.class)
	public void parseToDate() {
		DateUtils.parseToDate(LocalDateTime.now().toString(), "dd.MM.yyyy", TimeZone.getDefault());
	}

	@Test
	public void getUTCTimeFromDateTest() {
		Date date = new Date();
		SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
		dateFormatter.setTimeZone(TimeZone.getTimeZone(ZoneId.of("UTC")));
		String expectedDate = dateFormatter.format(date);
		String actualDate = DateUtils.getUTCTimeFromDate(date);
		assertTrue(expectedDate.equals(actualDate));
	}
}
