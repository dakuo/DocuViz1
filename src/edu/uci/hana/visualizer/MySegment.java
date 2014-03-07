package edu.uci.hana.visualizer;

import com.google.gson.annotations.Expose;

public class MySegment {

	private int segmentId ;

	private int start_index ;
	private int end_index ;
	
	private int new_start_index; // the start index in the newer revisions
	private int new_end_index; // the end index in the newer revisions
	
	@Expose
	private int segmentLength ;
	@Expose
	private int authorId;
	
	private String author;
	
	private String content ;
	private boolean visible;
	@Expose
	private int fatherSegmentIndex;
	@Expose
	private int offsetInFatherSegment;
	
	MySegment(){
		setFatherSegmentIndex(-1);
		setOffsetInFatherSegment(0);
	}

	public int getSegmentId() {
		return segmentId;
	}


	public void setSegmentId(int segmentId) {
		this.segmentId = segmentId;
	}


	public int getStartIndex() {
		return start_index;
	}


	public void setStartIndex(int startIndex) {
		this.start_index = startIndex;
		this.new_start_index = startIndex;
	}


	public int getEndIndex() {
		return end_index;
	}


	public void setEndIndex(int endIndex) {
		this.end_index = endIndex;
		this.new_end_index = endIndex;
	}


	public int getLength() {
		return (int)segmentLength;
	}



	public void setLength(int length) {
		this.segmentLength = length;
	}


	public String getAuthor() {
		return author;
	}

	//TODO I deleted a set authorId function in this setAuthor function, need to be handle in uper level
	public void setAuthor(String author) {
		this.author = author;
	}

	public String getContent() {
		return content;
	}


	public void setContent(String content) {
		this.content = content;
	}


	public boolean isVisible() {
		return visible;
	}


	public void setVisible(boolean visible) {
		this.visible = visible;
	}


	public String toString(){
		return " segmentId: "+ getSegmentId() +
				" \n author: " + getAuthor() +
				" \n start_index: " + getStartIndex()+
				" \n segmentLength: " + getLength()+
				" \n end_index: "+getEndIndex()+
				" \n content: " + getContent()
					;
	}


	public int getAuthorId() {
		return authorId;
	}


	public void setAuthorId(int authorId) {
		this.authorId = authorId;
	}

	public int getOffsetInFatherSegment() {
		return offsetInFatherSegment;
	}

	public void setOffsetInFatherSegment(int offsetInFatherSegment) {
		this.offsetInFatherSegment = offsetInFatherSegment;
	}

	public int getFatherSegmentIndex() {
		return fatherSegmentIndex;
	}

	public void setFatherSegmentIndex(int fatherSegmentIndex) {
		this.fatherSegmentIndex = fatherSegmentIndex;
	}

	public int getNewStartIndex() {
		return new_start_index;
	}

	public void setNewStartIndex(int new_start_index) {
		this.new_start_index = new_start_index;
	}

	public int getNewEndIndex() {
		return new_end_index;
	}

	public void setNewEndIndex(int new_end_index) {
		this.new_end_index = new_end_index;
	}

}
