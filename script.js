function analyzeHeader(){

let header = document.getElementById("headerInput").value;


fetch("http://127.0.0.1:5000/analyze",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({
header:header
})

})

.then(response => response.json())

.then(data => {

let classification = document.getElementById("classification");
let score = document.getElementById("score");
let indicators = document.getElementById("indicators");


classification.innerHTML = data.result;
score.innerHTML = "Risk Score: " + data.score;

let warningBox = document.getElementById("warning");

if(data.warning){
    warningBox.innerHTML = data.warning;
}
else{
    warningBox.innerHTML = "";
}


if(data.result.includes("HIGH"))
classification.className="high";

else if(data.result.includes("SUSPICIOUS"))
classification.className="medium";

else
classification.className="low";


indicators.innerHTML="<h3>Indicators Found</h3>";


for(let key in data.features){

if(data.features[key]){

indicators.innerHTML += "- "+key+"<br>";

}

}


});

}


function clearBox(){

document.getElementById("headerInput").value="";

document.getElementById("classification").innerHTML=
"Waiting for analysis...";

document.getElementById("score").innerHTML="";

document.getElementById("indicators").innerHTML="";

}