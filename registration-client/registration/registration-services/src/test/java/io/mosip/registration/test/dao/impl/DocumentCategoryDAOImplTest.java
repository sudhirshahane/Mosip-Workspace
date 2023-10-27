package io.mosip.registration.test.dao.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import io.mosip.registration.dao.impl.DocumentCategoryDAOImpl;
import io.mosip.registration.entity.DocumentCategory;
import io.mosip.registration.entity.id.GenericId;
import io.mosip.registration.repositories.DocumentCategoryRepository;

public class DocumentCategoryDAOImplTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();
	@InjectMocks
	private DocumentCategoryDAOImpl registrationDocumentCategoryDAOImpl;
	@Mock
	private DocumentCategoryRepository registrationDocumentCategoryRepository;

	@Test
	public void test() {
		DocumentCategory documentCategory = new DocumentCategory();
		documentCategory.setDescription("description");
		documentCategory.setName("name");
		// documentCategory.setCreatedTimesZone(timestamp);
		documentCategory.setCrBy("createdBy");
		// documentCategory.setDeletedTimesZone(timestamp);
		documentCategory.setLangCode("languageCode");
//		GenericId genericId = new GenericId();
		documentCategory.setIsActive(true);
		documentCategory.setCode("code");
		// documentCategory.setGenericId(genericId);
		List<DocumentCategory> list = new ArrayList<>();
		list.add(documentCategory);

		Mockito.when(registrationDocumentCategoryRepository.findAll()).thenReturn(list);

		assertEquals(list, registrationDocumentCategoryDAOImpl.getDocumentCategories());

	}

	@Test
	public void getDocumentCategoriesByLangCodeTest() {
		Mockito.when(registrationDocumentCategoryRepository.findByIsActiveTrueAndLangCode("eng"))
				.thenReturn(new ArrayList<>());

		assertNotNull(registrationDocumentCategoryDAOImpl.getDocumentCategoriesByLangCode("eng"));

	}

	@Test
	public void getDocumentCategorieByCodeTest() {

		DocumentCategory documentCategory = new DocumentCategory();
		documentCategory.setDescription("description");
		documentCategory.setName("name");
		// documentCategory.setCreatedTimesZone(timestamp);
		documentCategory.setCrBy("createdBy");
		// documentCategory.setDeletedTimesZone(timestamp);
		documentCategory.setLangCode("languageCode");
//		GenericId genericId = new GenericId();
		documentCategory.setIsActive(true);
		documentCategory.setCode("code");

		Mockito.when(
				registrationDocumentCategoryRepository.findByIsActiveTrueAndLangCode("languageCode"))
				.thenReturn(Arrays.asList(documentCategory));

		assertEquals(Arrays.asList(documentCategory), registrationDocumentCategoryDAOImpl.getDocumentCategoriesByLangCode("languageCode"));

	}
	
	
	@Test
	public void getDocumentCategoryByCodeAndByLangCodeTest() {
		DocumentCategory documentCategory = new DocumentCategory();
		Mockito.when(registrationDocumentCategoryRepository.findByIsActiveTrueAndCodeAndLangCode(Mockito.anyString(), Mockito.anyString()))
				.thenReturn(documentCategory);
		assertNotNull(registrationDocumentCategoryDAOImpl.getDocumentCategoryByCodeAndByLangCode(Mockito.anyString(), Mockito.anyString()));

	}

}
