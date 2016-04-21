package com.stratio.specs;


import com.stratio.exceptions.DBException;
import com.stratio.tests.utils.ThreadProperty;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class MongoToolsIT extends BaseGSpec{
    GivenGSpec commonspecG;

    public MongoToolsIT() {
        ThreadProperty.set("class", this.getClass().getCanonicalName());
        this.commonspec = new CommonG();
        commonspecG = new GivenGSpec(this.commonspec);
    }


    String doc;

    String db = "mongoITDB";
    String collection = "testCollection";


    @BeforeClass
    public void prepareMongo() throws DBException {
        commonspec.getMongoDBClient().connect();
        commonspec.getMongoDBClient().connectToMongoDBDataBase(db);
    }

    @Test
    public void insertionAtMongo_success() {
        doc = "{\n" +
                "  \"id\":\"id\",\n" +
                "  \"name\":\"name\",\n" +
                "  \"description\":\"description\",\n" +
                "  \"groups\": [{\"id\":\"groupname\",\"name\":\"groupname\"}],\n" +
                "  \"roles\": [\"rolesid\"]\n" +
                "}";

        commonspec.getLogger().debug("Verifying if the collection {} exists at {}", this.db, this.collection);
        commonspec.getMongoDBClient().insertDocIntoMongoDBCollection(collection, doc);
        assertThat(commonspec.getMongoDBClient().exitsCollections(collection)).as("The collection has been correctly created.").isEqualTo(true);
        commonspec.getLogger().debug("Verifying if a document exists at {}", this.collection);
        assertThat(commonspec.getMongoDBClient().getMongoDBCollection(collection).getCount()).as("One doc has been inserted.").isEqualTo(1);
        commonspec.getLogger().debug("Verifying the document {}", this.collection);
        assertThat(commonspec.getMongoDBClient().getMongoDBCollection(collection).find().one().toString()).as("Doc contains {}",doc).contains("rolesid");

    }


    @Test(expectedExceptions = com.mongodb.util.JSONParseException.class)
    public void insertionAtMongo_malformedFail() {
        doc = "}";
        commonspec.getLogger().debug("Verifying document can't be malformed");
        commonspec.getMongoDBClient().insertDocIntoMongoDBCollection(collection, doc);
    }

    @Test(expectedExceptions = java.lang.IllegalArgumentException.class)
    public void insertionAtMongo_nullFail() {
        doc = "";
        commonspec.getLogger().debug("Verifying document cant be null");
        commonspec.getMongoDBClient().insertDocIntoMongoDBCollection(collection, doc);
    }


    @AfterClass
    public  void cleanMongo() {
        commonspec.getMongoDBClient().dropMongoDBDataBase(db);
        commonspec.getMongoDBClient().disconnect();
    }
}
