/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.json.testMapping;

import be.atbash.json.JSONValue;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TestMapPublic {

    @Test
    public void testObjInts() {
        String s = "{\"vint\":[1,2,3]}";
        T1 r = JSONValue.parse(s, T1.class);
        assertThat(r.vint[2]).isEqualTo(3);
    }

    String MultiTyepJson = "{\"name\":\"B\",\"age\":120,\"cost\":12000,\"flag\":3,\"valid\":true,\"f\":1.2,\"d\":1.5,\"l\":12345678912345}";

    @Test
    public void testObjMixte() {
        T2 r = JSONValue.parse(MultiTyepJson, T2.class);

        assertThat(r.name).isEqualTo("B");

        assertThat(r.age).isEqualTo(Short.valueOf("120"));
        assertThat(r.cost).isEqualTo(12000);
        assertThat(r.flag).isEqualTo(Byte.valueOf("3"));
        assertThat(r.valid).isTrue();
        assertThat(r.f).isEqualTo(1.2F);
        assertThat(r.d).isEqualTo(1.5);
        assertThat(r.l).isEqualTo(12345678912345L);
    }

    @Test
    public void testObjMixtePrim() {
        T3 r = JSONValue.parse(MultiTyepJson, T3.class);
        assertThat(r.name).isEqualTo("B");

        assertThat(r.age).isEqualTo(Short.valueOf("120"));
        assertThat(r.cost).isEqualTo(12000);
        assertThat(r.flag).isEqualTo(Byte.valueOf("3"));
        assertThat(r.valid).isTrue();
        assertThat(r.f).isEqualTo(1.2F);
        assertThat(r.d).isEqualTo(1.5);
        assertThat(r.l).isEqualTo(12345678912345L);
    }

    public static class T1 {
        public int[] vint;
    }

    public static class T2 {
        public String name;
        public short age;
        public int cost;
        public byte flag;
        public boolean valid;
        public float f;
        public double d;
        public long l;
    }

    public static class T3 {
        public String name;
        public Short age;
        public Integer cost;
        public Byte flag;
        public Boolean valid;
        public Float f;
        public Double d;
        public Long l;
    }

}
